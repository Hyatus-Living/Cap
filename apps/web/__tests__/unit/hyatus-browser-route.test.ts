import { NextRequest } from "next/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("@cap/env", () => ({
	serverEnv: () => ({ NEXTAUTH_SECRET: "test-nextauth-secret" }),
}));

import { GET } from "@/app/api/auth/hyatus/route";

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
});
