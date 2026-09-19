import { createHash } from "node:crypto";
import { nanoId } from "@cap/database/helpers";
import * as Db from "@cap/database/schema";
import { serverEnv } from "@cap/env";
import { type Agent, Organisation, User } from "@cap/web-domain";
import { and, eq, sql } from "drizzle-orm";
import { Effect } from "effect";
import type { Database, DbClient } from "./Database.ts";

const delegatedTokenPattern = /^hyatus_cap_[A-Za-z0-9_-]{43}$/;
const introspectionTimeoutMs = 3_000;

export const delegatedAgentScopes = new Set<Agent.AgentScope>([
	"caps:read",
	"caps:comment",
	"caps:write",
	"profile:read",
	"caps:upload",
	"caps:delete",
	"library:read",
	"library:write",
]);

export type HyatusCapContext = {
	subject: string;
	email: string;
	name: string | null;
	scopes: Set<Agent.AgentScope>;
	expiresAt: Date;
};

export class HyatusCapIntrospectionError extends Error {
	readonly kind: "invalid" | "unavailable";

	constructor(kind: "invalid" | "unavailable") {
		super(`Hyatus Cap introspection ${kind}`);
		this.kind = kind;
	}
}

type Fetcher = (
	input: string | URL | Request,
	init?: RequestInit,
) => Promise<Response>;

const invalidIntrospection = () => new HyatusCapIntrospectionError("invalid");
const unavailableIntrospection = () =>
	new HyatusCapIntrospectionError("unavailable");

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

export const isHyatusCapDelegatedToken = (token: string) =>
	delegatedTokenPattern.test(token);

export async function requestHyatusCapContext({
	token,
	introspectionUrl,
	resource,
	fetcher = fetch,
}: {
	token: string;
	introspectionUrl: string;
	resource: string;
	fetcher?: Fetcher;
}): Promise<HyatusCapContext> {
	if (!isHyatusCapDelegatedToken(token)) throw invalidIntrospection();

	let introspectionEndpoint: URL;
	try {
		introspectionEndpoint = new URL(introspectionUrl);
	} catch {
		throw unavailableIntrospection();
	}
	if (
		introspectionEndpoint.protocol !== "https:" ||
		introspectionEndpoint.username ||
		introspectionEndpoint.password
	) {
		throw unavailableIntrospection();
	}

	let response: Response;
	try {
		response = await fetcher(introspectionEndpoint, {
			method: "GET",
			headers: {
				Accept: "application/json",
				Authorization: `Bearer ${token}`,
				"Cache-Control": "no-store",
			},
			cache: "no-store",
			credentials: "omit",
			redirect: "error",
			signal: AbortSignal.timeout(introspectionTimeoutMs),
		});
	} catch {
		throw unavailableIntrospection();
	}

	if (response.status === 401 || response.status === 403) {
		throw invalidIntrospection();
	}
	if (!response.ok) throw unavailableIntrospection();

	let payload: unknown;
	try {
		payload = await response.json();
	} catch {
		throw unavailableIntrospection();
	}

	if (
		!isRecord(payload) ||
		payload.authenticated !== true ||
		payload.resource !== resource ||
		!isRecord(payload.user) ||
		typeof payload.user.id !== "string" ||
		payload.user.id.length === 0 ||
		payload.user.id.length > 255 ||
		typeof payload.user.email !== "string" ||
		payload.user.emailVerified !== true ||
		!Array.isArray(payload.scopes) ||
		typeof payload.expiresAt !== "string"
	) {
		throw invalidIntrospection();
	}

	const email = payload.user.email.trim().toLowerCase();
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
		throw invalidIntrospection();
	}
	if (payload.user.name !== null && typeof payload.user.name !== "string") {
		throw invalidIntrospection();
	}

	const scopes = payload.scopes.filter(
		(scope): scope is Agent.AgentScope =>
			typeof scope === "string" &&
			delegatedAgentScopes.has(scope as Agent.AgentScope),
	);
	if (
		scopes.length !== payload.scopes.length ||
		new Set(scopes).size !== scopes.length ||
		!scopes.includes("caps:read")
	) {
		throw invalidIntrospection();
	}

	const expiresAt = new Date(payload.expiresAt);
	if (
		!Number.isFinite(expiresAt.getTime()) ||
		expiresAt.getTime() <= Date.now()
	) {
		throw invalidIntrospection();
	}

	return {
		subject: payload.user.id,
		email,
		name: payload.user.name?.trim() || null,
		scopes: new Set(scopes),
		expiresAt,
	};
}

export const introspectHyatusCapToken = (
	token: string,
): Effect.Effect<HyatusCapContext, HyatusCapIntrospectionError> => {
	const introspectionUrl = serverEnv().HYATUS_CAP_INTROSPECTION_URL;
	if (!introspectionUrl) {
		return Effect.fail(unavailableIntrospection());
	}
	return Effect.tryPromise({
		try: () =>
			requestHyatusCapContext({
				token,
				introspectionUrl,
				resource: serverEnv().WEB_URL,
			}),
		catch: (cause) =>
			cause instanceof HyatusCapIntrospectionError
				? cause
				: unavailableIntrospection(),
	});
};

type ResolvedHyatusCapUser = {
	id: User.UserId;
	email: string;
	activeOrganizationId: Organisation.OrganisationId;
};

export type ResolveHyatusCapIdentityResult =
	| { state: "resolved"; user: ResolvedHyatusCapUser }
	| { state: "link_required" }
	| { state: "invalid_binding" };

export const resolveHyatusCapIdentityWithDb = async (
	db: DbClient,
	context: HyatusCapContext,
): Promise<ResolveHyatusCapIdentityResult> => {
	const [existing] = await db
		.select({
			id: Db.users.id,
			email: Db.users.email,
			activeOrganizationId: Db.users.activeOrganizationId,
		})
		.from(Db.hyatusCapIdentities)
		.innerJoin(Db.users, eq(Db.hyatusCapIdentities.userId, Db.users.id))
		.where(eq(Db.hyatusCapIdentities.hyatusSubject, context.subject))
		.limit(1);
	if (existing) {
		if (!existing.activeOrganizationId) return { state: "invalid_binding" };
		return {
			state: "resolved",
			user: {
				id: existing.id,
				email: existing.email,
				activeOrganizationId: existing.activeOrganizationId,
			},
		};
	}

	return db.transaction(async (tx): Promise<ResolveHyatusCapIdentityResult> => {
		const userId = User.UserId.make(nanoId());
		const organizationId = Organisation.OrganisationId.make(nanoId());

		await tx
			.insert(Db.hyatusCapIdentities)
			.values({
				id: nanoId(),
				hyatusSubject: context.subject,
				userId,
				emailAtLink: context.email,
			})
			.onDuplicateKeyUpdate({
				set: {
					hyatusSubject: sql`${Db.hyatusCapIdentities.hyatusSubject}`,
				},
			});

		const [claimed] = await tx
			.select({ userId: Db.hyatusCapIdentities.userId })
			.from(Db.hyatusCapIdentities)
			.where(eq(Db.hyatusCapIdentities.hyatusSubject, context.subject))
			.for("update")
			.limit(1);
		if (!claimed) return { state: "invalid_binding" };
		if (claimed.userId !== userId) {
			const [concurrent] = await tx
				.select({
					id: Db.users.id,
					email: Db.users.email,
					activeOrganizationId: Db.users.activeOrganizationId,
				})
				.from(Db.hyatusCapIdentities)
				.innerJoin(Db.users, eq(Db.hyatusCapIdentities.userId, Db.users.id))
				.where(eq(Db.hyatusCapIdentities.hyatusSubject, context.subject))
				.for("update")
				.limit(1);
			if (!concurrent?.activeOrganizationId) {
				return { state: "invalid_binding" };
			}
			return {
				state: "resolved",
				user: {
					id: concurrent.id,
					email: concurrent.email,
					activeOrganizationId: concurrent.activeOrganizationId,
				},
			};
		}

		await tx
			.insert(Db.users)
			.values({
				id: userId,
				email: context.email,
				emailVerified: new Date(),
				name: context.name ?? context.email.split("@")[0],
				activeOrganizationId: organizationId,
				defaultOrgId: organizationId,
				marketingOrigin: "independent",
			})
			.onDuplicateKeyUpdate({
				set: { email: sql`${Db.users.email}` },
			});
		const [claimedEmail] = await tx
			.select({ id: Db.users.id })
			.from(Db.users)
			.where(eq(Db.users.email, context.email))
			.for("update")
			.limit(1);
		if (claimedEmail?.id !== userId) {
			await tx
				.delete(Db.hyatusCapIdentities)
				.where(
					and(
						eq(Db.hyatusCapIdentities.hyatusSubject, context.subject),
						eq(Db.hyatusCapIdentities.userId, userId),
					),
				);
			return { state: "link_required" };
		}
		await tx.insert(Db.organizations).values({
			id: organizationId,
			ownerId: userId,
			name: "My Organization",
		});
		await tx.insert(Db.organizationMembers).values({
			id: nanoId(),
			organizationId,
			userId,
			role: "owner",
		});

		return {
			state: "resolved",
			user: {
				id: userId,
				email: context.email,
				activeOrganizationId: organizationId,
			},
		};
	});
};

export const resolveHyatusCapIdentity = (
	database: Database,
	context: HyatusCapContext,
) => database.use((db) => resolveHyatusCapIdentityWithDb(db, context));

export type LinkHyatusCapIdentityResult =
	| { state: "linked" }
	| { state: "email_mismatch" }
	| { state: "subject_conflict" }
	| { state: "user_conflict" }
	| { state: "invalid_user" };

export const linkHyatusCapIdentityWithDb = (
	db: DbClient,
	context: HyatusCapContext,
	userId: User.UserId,
) =>
	db.transaction(async (tx): Promise<LinkHyatusCapIdentityResult> => {
		const [user] = await tx
			.select({
				id: Db.users.id,
				email: Db.users.email,
				emailVerified: Db.users.emailVerified,
				activeOrganizationId: Db.users.activeOrganizationId,
			})
			.from(Db.users)
			.where(eq(Db.users.id, userId))
			.for("update")
			.limit(1);
		if (!user?.activeOrganizationId) return { state: "invalid_user" };
		if (!user.emailVerified || user.email.toLowerCase() !== context.email) {
			return { state: "email_mismatch" };
		}

		const [userBinding] = await tx
			.select({ subject: Db.hyatusCapIdentities.hyatusSubject })
			.from(Db.hyatusCapIdentities)
			.where(eq(Db.hyatusCapIdentities.userId, userId))
			.limit(1);
		if (userBinding && userBinding.subject !== context.subject) {
			return { state: "user_conflict" };
		}

		await tx
			.insert(Db.hyatusCapIdentities)
			.values({
				id: nanoId(),
				hyatusSubject: context.subject,
				userId,
				emailAtLink: context.email,
			})
			.onDuplicateKeyUpdate({
				set: {
					hyatusSubject: sql`${Db.hyatusCapIdentities.hyatusSubject}`,
				},
			});

		const [subjectBinding] = await tx
			.select({ userId: Db.hyatusCapIdentities.userId })
			.from(Db.hyatusCapIdentities)
			.where(eq(Db.hyatusCapIdentities.hyatusSubject, context.subject))
			.limit(1);
		if (subjectBinding?.userId !== userId) {
			return { state: "subject_conflict" };
		}
		return { state: "linked" };
	});

export const linkHyatusCapIdentity = (
	database: Database,
	context: HyatusCapContext,
	userId: User.UserId,
) => database.use((db) => linkHyatusCapIdentityWithDb(db, context, userId));

export const hyatusCapTokenId = (token: string) =>
	`hyatus:${createHash("sha256").update(token).digest("hex").slice(0, 24)}`;
