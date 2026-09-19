import { randomUUID } from "node:crypto";
import {
	hyatusCapIdentities,
	organizationMembers,
	organizations,
	users,
} from "@cap/database/schema";
import { Organisation, User } from "@cap/web-domain";
import { eq } from "drizzle-orm";
import { drizzle, type MySql2Database } from "drizzle-orm/mysql2";
import { createPool, type Pool } from "mysql2/promise";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { DbClient } from "../../../../packages/web-backend/src/Database";
import {
	type HyatusCapContext,
	linkHyatusCapIdentityWithDb,
	resolveHyatusCapIdentityWithDb,
} from "../../../../packages/web-backend/src/HyatusCapAuth";

const databaseUrl = process.env.CAP_HYATUS_TEST_DATABASE_URL;
let databaseClient: MySql2Database | undefined;

const database = () => {
	if (!databaseClient) throw new Error("Test database is not connected.");
	return databaseClient as DbClient;
};

const id = () => randomUUID().replaceAll("-", "").slice(0, 15);

const context = (subject: string, email: string): HyatusCapContext => ({
	subject,
	email,
	name: `User ${subject}`,
	scopes: new Set([
		"caps:read",
		"caps:comment",
		"caps:write",
		"caps:upload",
		"caps:delete",
		"profile:read",
		"library:read",
		"library:write",
	]),
	expiresAt: new Date(Date.now() + 60_000),
});

const createExistingCapUser = async (email: string) => {
	const userId = User.UserId.make(id());
	const organizationId = Organisation.OrganisationId.make(id());
	await database().insert(users).values({
		id: userId,
		email,
		emailVerified: new Date(),
		name: "Existing Cap User",
		activeOrganizationId: organizationId,
		defaultOrgId: organizationId,
	});
	await database().insert(organizations).values({
		id: organizationId,
		ownerId: userId,
		name: "Existing Organization",
	});
	await database().insert(organizationMembers).values({
		id: id(),
		userId,
		organizationId,
		role: "owner",
	});
	return { userId, organizationId };
};

describe.runIf(Boolean(databaseUrl))(
	"Hyatus Cap identities with an isolated MySQL database",
	() => {
		let pool: Pool | undefined;

		beforeAll(async () => {
			if (!databaseUrl) throw new Error("Missing isolated test database URL.");
			const url = new URL(databaseUrl);
			if (
				url.protocol !== "mysql:" ||
				!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
				!/^\/cap_hyatus_[a-z0-9_]+$/.test(url.pathname)
			) {
				throw new Error(
					"Hyatus Cap tests require a session-scoped local database.",
				);
			}
			pool = createPool(databaseUrl);
			databaseClient = drizzle(pool);
			await database().select().from(hyatusCapIdentities).limit(1);
		});

		afterAll(async () => {
			await pool?.end();
			databaseClient = undefined;
		});

		it("provisions distinct personal libraries for distinct Hyatus users", async () => {
			const [first, second] = await Promise.all([
				resolveHyatusCapIdentityWithDb(
					database(),
					context(`subject-${id()}`, `${id()}@hyatus.com`),
				),
				resolveHyatusCapIdentityWithDb(
					database(),
					context(`subject-${id()}`, `${id()}@hyatus.com`),
				),
			]);
			expect(first.state).toBe("resolved");
			expect(second.state).toBe("resolved");
			if (first.state !== "resolved" || second.state !== "resolved") return;
			expect(first.user.id).not.toBe(second.user.id);
			expect(first.user.activeOrganizationId).not.toBe(
				second.user.activeOrganizationId,
			);
		});

		it("serializes concurrent provisioning to one subject mapping", async () => {
			const delegated = context(`subject-${id()}`, `${id()}@hyatus.com`);
			const resolved = await Promise.all(
				Array.from({ length: 8 }, () =>
					resolveHyatusCapIdentityWithDb(database(), delegated),
				),
			);
			const userIds = resolved.map((result) =>
				result.state === "resolved" ? result.user.id : result.state,
			);
			expect(new Set(userIds).size).toBe(1);
			expect(
				await database()
					.select()
					.from(hyatusCapIdentities)
					.where(eq(hyatusCapIdentities.hyatusSubject, delegated.subject)),
			).toHaveLength(1);
		});

		it("requires explicit linking and preserves the existing Cap account", async () => {
			const email = `${id()}@hyatus.com`;
			const existing = await createExistingCapUser(email);
			const delegated = context(`subject-${id()}`, email);

			expect(
				await resolveHyatusCapIdentityWithDb(database(), delegated),
			).toEqual({ state: "link_required" });
			expect(
				await linkHyatusCapIdentityWithDb(
					database(),
					delegated,
					existing.userId,
				),
			).toEqual({ state: "linked" });
			const resolved = await resolveHyatusCapIdentityWithDb(
				database(),
				delegated,
			);
			expect(resolved).toMatchObject({
				state: "resolved",
				user: {
					id: existing.userId,
					activeOrganizationId: existing.organizationId,
				},
			});
		});

		it("rejects immutable subject and Cap account link conflicts", async () => {
			const first = await createExistingCapUser(`${id()}@hyatus.com`);
			const secondEmail = `${id()}@hyatus.com`;
			const second = await createExistingCapUser(secondEmail);
			const firstContext = context(`subject-${id()}`, secondEmail);
			const otherSubject = context(`subject-${id()}`, secondEmail);

			expect(
				await linkHyatusCapIdentityWithDb(
					database(),
					firstContext,
					second.userId,
				),
			).toEqual({ state: "linked" });
			expect(
				await linkHyatusCapIdentityWithDb(
					database(),
					otherSubject,
					second.userId,
				),
			).toEqual({ state: "user_conflict" });
			expect(
				await linkHyatusCapIdentityWithDb(
					database(),
					firstContext,
					first.userId,
				),
			).toEqual({ state: "email_mismatch" });
		});
	},
);
