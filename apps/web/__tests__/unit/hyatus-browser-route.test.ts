import { NextRequest } from "next/server";
import { encode } from "next-auth/jwt";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	db: vi.fn(),
	requestContext: vi.fn(),
	resolveIdentity: vi.fn(),
}));

vi.mock("server-only", () => ({}));
vi.mock("@cap/database", () => ({ db: mocks.db }));
vi.mock("@cap/database/auth/hyatus-browser", () => ({
	requestHyatusBrowserContext: mocks.requestContext,
}));
vi.mock("@cap/database/schema", () => ({
	users: {
		authSessionVersion: "users.authSessionVersion",
		email: "users.email",
		id: "users.id",
		image: "users.image",
		lastName: "users.lastName",
		name: "users.name",
	},
}));
vi.mock("@cap/web-backend", () => ({
	resolveHyatusCapIdentityWithDb: mocks.resolveIdentity,
}));
vi.mock("drizzle-orm", () => ({ eq: vi.fn() }));

vi.mock("@cap/env", () => ({
	serverEnv: () => ({
		NEXTAUTH_SECRET: "test-nextauth-secret",
		WEB_URL: "https://videos.gptguest.com",
	}),
}));

import { GET as callbackGET } from "@/app/api/auth/hyatus/callback/route";
import { GET } from "@/app/api/auth/hyatus/route";
import {
	HYATUS_BROWSER_INTENT_COOKIE,
	HYATUS_BROWSER_INTENT_SALT,
} from "@/lib/hyatus-browser-auth";

afterEach(() => {
	vi.unstubAllGlobals();
	vi.clearAllMocks();
});

describe("Hyatus browser authorization route", () => {
	it("sets a bounded encrypted intent cookie and sends PKCE parameters", async () => {
		const response = await GET(
			new NextRequest(
				"https://videos.gptguest.com/api/auth/hyatus?returnTo=/s/video-id",
			),
		);
		const location = new URL(response.headers.get("location") ?? "");
		expect(location.origin).toBe("https://auth.gptguest.com");
		expect(location.pathname).toBe("/v1/cap/browser/authorize");
		expect(location.searchParams.get("client_id")).toBe("hyatus-cap-web");
		expect(location.searchParams.get("redirect_uri")).toBe(
			"https://videos.gptguest.com/api/auth/hyatus/callback",
		);
		expect(location.searchParams.get("response_type")).toBe("code");
		expect(location.searchParams.get("code_challenge_method")).toBe("S256");
		expect(location.searchParams.get("code_challenge")).toMatch(
			/^[A-Za-z0-9_-]{43}$/,
		);
		expect(location.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);

		const cookie = response.headers.get("set-cookie") ?? "";
		expect(cookie).toContain("hyatus-cap.browser-intent=");
		expect(cookie).toContain("HttpOnly");
		expect(cookie).toContain("Secure");
		expect(cookie).toContain("SameSite=lax");
		expect(cookie).toContain("Path=/api/auth/hyatus");
		expect(cookie).toContain("Max-Age=600");
		expect(response.headers.get("cache-control")).toBe("private, no-store");
	});

	it("uses the configured public origin for callback errors", async () => {
		const response = await callbackGET(
			new NextRequest("https://0.0.0.0:3000/api/auth/hyatus/callback"),
		);

		expect(response.headers.get("location")).toBe(
			"https://videos.gptguest.com/login?error=HyatusSessionExpired",
		);
	});

	it("uses the configured public origin after a successful callback", async () => {
		const state = "a".repeat(43);
		const intent = await encode({
			secret: "test-nextauth-secret",
			salt: HYATUS_BROWSER_INTENT_SALT,
			maxAge: 600,
			token: {
				kind: "hyatus-cap-browser-intent",
				state,
				codeVerifier: "b".repeat(43),
				returnTo: "/s/video-id",
				issuedAt: Date.now(),
			},
		});
		const expiresAt = new Date(Date.now() + 60 * 60 * 1_000);
		mocks.requestContext.mockResolvedValue({
			subject: "hyatus-user",
			email: "employee@hyatus.com",
			emailVerified: true,
			status: "active",
			permissions: new Set(["caps:read"]),
			scopes: new Set(["caps:read"]),
			expiresAt,
		});
		mocks.resolveIdentity.mockResolvedValue({
			state: "resolved",
			user: { id: "cap-user" },
		});
		mocks.db.mockReturnValue({
			select: () => ({
				from: () => ({
					where: () => ({
						limit: async () => [
							{
								id: "cap-user",
								name: "Employee",
								lastName: null,
								email: "employee@hyatus.com",
								image: null,
								authSessionVersion: 0,
							},
						],
					}),
				}),
			}),
		});
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(
				Response.json({
					accessToken: `hyatus_cap_browser_${"c".repeat(43)}`,
					tokenType: "Bearer",
					resource: "https://videos.gptguest.com",
					scopes: ["caps:read"],
					expiresAt: expiresAt.toISOString(),
				}),
			),
		);

		const response = await callbackGET(
			new NextRequest(
				`https://0.0.0.0:3000/api/auth/hyatus/callback?code=code&state=${state}`,
				{
					headers: {
						cookie: `${HYATUS_BROWSER_INTENT_COOKIE}=${intent}`,
					},
				},
			),
		);

		expect(response.headers.get("location")).toBe(
			"https://videos.gptguest.com/s/video-id",
		);
	});
});
