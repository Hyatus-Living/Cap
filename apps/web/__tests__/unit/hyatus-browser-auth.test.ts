import { authOptions } from "@cap/database/auth/auth-options";
import { requestHyatusBrowserContext } from "@cap/database/auth/hyatus-browser";
import { describe, expect, it } from "vitest";
import {
	createCodeChallenge,
	isHyatusBrowserUser,
	safeReturnPath,
	validIntent,
} from "@/lib/hyatus-browser-auth";

const state = "a".repeat(43);
const verifier = "b".repeat(43);

describe("Hyatus browser auth", () => {
	it("prevents browser sessions from issuing persistent Cap credentials", () => {
		expect(isHyatusBrowserUser({ hyatusVerified: true })).toBe(true);
		expect(isHyatusBrowserUser({ hyatusVerified: false })).toBe(false);
		expect(isHyatusBrowserUser({})).toBe(false);
	});

	it("creates an S256 PKCE challenge", () => {
		expect(createCodeChallenge(verifier)).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(createCodeChallenge(verifier)).not.toBe(verifier);
	});

	it.each([
		["/s/video?view=timeline", "/s/video?view=timeline"],
		["https://attacker.example/path", "/dashboard/caps"],
		["//attacker.example/path", "/dashboard/caps"],
		[null, "/dashboard/caps"],
	])("bounds the return path", (input, expected) => {
		expect(safeReturnPath(input)).toBe(expected);
	});

	it("requires a fresh intent and constant-length matching state", () => {
		const issuedAt = Date.now();
		const intent = {
			kind: "hyatus-cap-browser-intent",
			state,
			codeVerifier: verifier,
			returnTo: "/dashboard/caps",
			issuedAt,
		};
		expect(validIntent(intent, state, issuedAt + 1_000)).toBe(true);
		expect(validIntent(intent, "c".repeat(43), issuedAt + 1_000)).toBe(false);
		expect(validIntent(intent, state, issuedAt + 600_000)).toBe(false);
	});

	it("validates the browser token context and scope boundary", async () => {
		const expiresAt = new Date(Date.now() + 60_000).toISOString();
		const context = await requestHyatusBrowserContext({
			token: `hyatus_cap_browser_${"d".repeat(43)}`,
			resource: "https://videos.gptguest.com",
			fetcher: async (_input, init) => {
				expect(new Headers(init?.headers).get("authorization")).toMatch(
					/^Bearer hyatus_cap_browser_/,
				);
				return Response.json({
					authenticated: true,
					resource: "https://videos.gptguest.com",
					user: {
						id: "gptguest:employee",
						email: "Employee@Hyatus.com",
						name: "Employee",
						emailVerified: true,
					},
					scopes: ["caps:read"],
					expiresAt,
				});
			},
		});
		expect(context).toMatchObject({
			subject: "gptguest:employee",
			email: "employee@hyatus.com",
		});
		expect(context?.scopes.has("caps:read")).toBe(true);
	});

	it("rejects unrecognized browser scopes", async () => {
		const context = await requestHyatusBrowserContext({
			token: `hyatus_cap_browser_${"e".repeat(43)}`,
			resource: "https://videos.gptguest.com",
			fetcher: async () =>
				Response.json({
					authenticated: true,
					resource: "https://videos.gptguest.com",
					user: {
						id: "gptguest:employee",
						email: "employee@hyatus.com",
						name: null,
						emailVerified: true,
					},
					scopes: ["caps:read", "organizations:manage"],
					expiresAt: new Date(Date.now() + 60_000).toISOString(),
				}),
		});
		expect(context).toBeNull();
	});

	it("fails closed when the browser session is revoked", async () => {
		const context = await requestHyatusBrowserContext({
			token: `hyatus_cap_browser_${"f".repeat(43)}`,
			resource: "https://videos.gptguest.com",
			fetcher: async () =>
				Response.json({ authenticated: false }, { status: 401 }),
		});
		expect(context).toBeNull();
	});

	it("keeps the browser credential out of the client session", async () => {
		const sessionCallback = authOptions().callbacks?.session;
		expect(sessionCallback).toBeTypeOf("function");
		const result = await (
			sessionCallback as unknown as (input: {
				session: {
					user: { name: null; email: null; image: null };
					expires: string;
				};
				token: {
					id: string;
					hyatusBrowserAccessToken: string;
					hyatusScopes: string[];
					hyatusVerified: boolean;
				};
			}) => Promise<unknown>
		)({
			session: {
				user: { name: null, email: null, image: null },
				expires: new Date(Date.now() + 60_000).toISOString(),
			},
			token: {
				id: "cap-user-id",
				hyatusBrowserAccessToken: `hyatus_cap_browser_${"g".repeat(43)}`,
				hyatusScopes: ["caps:read"],
				hyatusVerified: true,
			},
		});
		expect(result).toMatchObject({
			user: {
				id: "cap-user-id",
				hyatusScopes: ["caps:read"],
				hyatusVerified: true,
			},
		});
		expect(JSON.stringify(result)).not.toContain("hyatus_cap_browser_");
	});
});
