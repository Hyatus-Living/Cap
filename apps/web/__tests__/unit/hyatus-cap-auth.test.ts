import { describe, expect, it, vi } from "vitest";
import {
	delegatedAgentScopes,
	type HyatusCapIntrospectionError,
	requestHyatusCapContext,
} from "../../../../packages/web-backend/src/HyatusCapAuth";

const token = `hyatus_cap_${"a".repeat(43)}`;
const resource = "https://videos.gptguest.com";
const introspectionUrl = "https://auth.gptguest.com/v1/cap/context";

const validPayload = (): {
	authenticated: boolean;
	resource: string;
	user: {
		id: string;
		email: string;
		name: string;
		emailVerified: boolean;
	};
	scopes: string[];
	expiresAt: string;
} => ({
	authenticated: true,
	resource,
	user: {
		id: "hyatus-user-1",
		email: "User@Hyatus.com",
		name: "Hyatus User",
		emailVerified: true,
	},
	scopes: Array.from(delegatedAgentScopes),
	expiresAt: new Date(Date.now() + 60_000).toISOString(),
});

const jsonResponse = (payload: unknown, status = 200) =>
	new Response(JSON.stringify(payload), {
		status,
		headers: { "Content-Type": "application/json" },
	});

describe("Hyatus delegated Cap authentication", () => {
	it("revalidates a delegated token with no cache or redirects", async () => {
		const fetcher = vi.fn(
			async (_input: string | URL | Request, _init?: RequestInit) =>
				jsonResponse(validPayload()),
		);
		const context = await requestHyatusCapContext({
			token,
			introspectionUrl,
			resource,
			fetcher,
		});
		await requestHyatusCapContext({
			token,
			introspectionUrl,
			resource,
			fetcher,
		});

		expect(context).toMatchObject({
			subject: "hyatus-user-1",
			email: "user@hyatus.com",
			name: "Hyatus User",
		});
		expect(fetcher).toHaveBeenCalledTimes(2);
		expect(fetcher.mock.calls[0]?.[1]).toMatchObject({
			method: "GET",
			cache: "no-store",
			credentials: "omit",
			redirect: "error",
		});
	});

	it("fails closed when Hyatus revokes the session", async () => {
		await expect(
			requestHyatusCapContext({
				token,
				introspectionUrl,
				resource,
				fetcher: async () => jsonResponse({ authenticated: false }, 401),
			}),
		).rejects.toMatchObject({
			kind: "invalid",
		} satisfies Partial<HyatusCapIntrospectionError>);
	});

	it("rejects the wrong resource", async () => {
		const payload = validPayload();
		payload.resource = "https://cap.so";
		await expect(
			requestHyatusCapContext({
				token,
				introspectionUrl,
				resource,
				fetcher: async () => jsonResponse(payload),
			}),
		).rejects.toMatchObject({ kind: "invalid" });
	});

	it.each(["caps:process", "billing:read", "organizations:manage"])(
		"rejects forbidden delegated scope %s",
		async (forbiddenScope) => {
			const payload = validPayload();
			payload.scopes = [...payload.scopes, forbiddenScope];
			await expect(
				requestHyatusCapContext({
					token,
					introspectionUrl,
					resource,
					fetcher: async () => jsonResponse(payload),
				}),
			).rejects.toMatchObject({ kind: "invalid" });
		},
	);

	it("treats network and malformed responses as unavailable", async () => {
		await expect(
			requestHyatusCapContext({
				token,
				introspectionUrl,
				resource,
				fetcher: async () => {
					throw new Error("offline");
				},
			}),
		).rejects.toMatchObject({ kind: "unavailable" });

		await expect(
			requestHyatusCapContext({
				token,
				introspectionUrl,
				resource,
				fetcher: async () => new Response("not-json"),
			}),
		).rejects.toMatchObject({ kind: "unavailable" });
	});
});
