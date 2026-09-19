import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	db: vi.fn(),
	getCurrentUser: vi.fn(),
}));

vi.mock("@cap/database", () => ({ db: mocks.db }));
vi.mock("@cap/database/auth/auth-options", () => ({
	decodeSessionToken: vi.fn(),
}));
vi.mock("@cap/database/auth/session", () => ({
	getCurrentUser: mocks.getCurrentUser,
}));
vi.mock("@cap/env", () => ({
	serverEnv: () => ({
		NEXTAUTH_SECRET: "test-secret",
		WEB_URL: "https://videos.gptguest.com",
		VERCEL_ENV: "production",
	}),
}));

import { app } from "@/app/api/desktop/[...route]/session";

describe("Hyatus browser credential isolation", () => {
	it("returns 403 without inserting a desktop API key", async () => {
		mocks.getCurrentUser.mockResolvedValue({
			id: "cap-user",
			hyatusVerified: true,
			hyatusScopes: new Set(["caps:read"]),
		});
		const response = await app.request("/request?type=api_key");

		expect(response.status).toBe(403);
		expect(mocks.db).not.toHaveBeenCalled();
	});
});
