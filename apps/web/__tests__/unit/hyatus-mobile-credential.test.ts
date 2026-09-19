import { Database } from "@cap/web-backend";
import { Effect, Exit } from "effect";
import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@cap/env", () => ({
	buildEnv: { NEXT_PUBLIC_WEB_URL: "https://videos.gptguest.com" },
	serverEnv: () => ({
		CAP_AWS_BUCKET: "cap-test",
		CAP_AWS_REGION: "us-east-1",
		DATABASE_URL: "mysql://cap:cap@127.0.0.1:3306/cap",
		NEXTAUTH_SECRET: "test-secret",
		NEXTAUTH_URL: "https://videos.gptguest.com",
		WEB_URL: "https://videos.gptguest.com",
	}),
}));

import { createMobileApiKey } from "@/app/api/mobile/[...route]/route";

describe("Hyatus mobile credential isolation", () => {
	it("fails before database access for a Hyatus browser session", async () => {
		const databaseUse = vi.fn();
		const exit = await Effect.runPromiseExit(
			createMobileApiKey({
				id: "cap-user" as never,
				hyatusVerified: true,
			}).pipe(
				Effect.provideService(
					Database,
					Database.make({
						use: () => {
							databaseUse();
							return Effect.die("unexpected database access");
						},
					}),
				),
			),
		);

		expect(Exit.isFailure(exit)).toBe(true);
		if (Exit.isFailure(exit)) {
			expect(String(exit.cause)).toContain("Forbidden");
			expect(String(exit.cause)).not.toContain("Service not found");
		}
		expect(databaseUse).not.toHaveBeenCalled();
	});
});
