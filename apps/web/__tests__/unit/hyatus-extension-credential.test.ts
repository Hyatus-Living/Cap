import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { canMintPersistentCredential } from "@cap/web-backend/src/CredentialPolicy";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(process.cwd(), "../..");
const source = (path: string) =>
	readFileSync(resolve(repositoryRoot, path), "utf8");

describe("Hyatus extension credential isolation", () => {
	it("denies persistent extension credentials for every Hyatus browser session", () => {
		expect(canMintPersistentCredential({ hyatusVerified: true })).toBe(false);
	});

	it("preserves extension credentials for regular Cap sessions", () => {
		expect(canMintPersistentCredential({})).toBe(true);
	});

	it.each([
		[
			"packages/web-backend/src/Extension/Http.ts",
			"if (!canMintPersistentCredential(currentUser.value))",
			"extensions.mintAuthKey(",
		],
		[
			"apps/web/app/(org)/dashboard/settings/account/server.ts",
			"if (!canMintPersistentCredential(currentUser))",
			"const token = createAgentAccessToken()",
		],
		[
			"apps/web/actions/developers/create-app.ts",
			"if (!canMintPersistentCredential(user))",
			"const appId = nanoId()",
		],
		[
			"apps/web/actions/developers/regenerate-keys.ts",
			"if (!canMintPersistentCredential(user))",
			"const [app] = await db()",
		],
		[
			"apps/web/app/cli/authorize/page.tsx",
			"if (!canMintPersistentCredential(currentUser))",
			"const code = createAgentAuthorizationCode()",
		],
	] as const)(
		"guards %s before issuing a credential",
		(path, guard, issuance) => {
			const file = source(path);
			const guardPosition = file.indexOf(guard);
			const issuancePosition = file.indexOf(issuance, guardPosition);
			expect(guardPosition).toBeGreaterThan(-1);
			expect(issuancePosition).toBeGreaterThan(guardPosition);
		},
	);
});
