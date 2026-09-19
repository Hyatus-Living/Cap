import type { Agent } from "@cap/web-domain";

const browserTokenPattern = /^hyatus_cap_browser_[A-Za-z0-9_-]{43}$/;
const introspectionTimeoutMs = 3_000;

export const HYATUS_BROWSER_RESOURCE = "https://videos.gptguest.com";

const allowedScopes = new Set<Agent.AgentScope>([
	"caps:read",
	"caps:comment",
	"caps:write",
	"profile:read",
	"caps:upload",
	"caps:delete",
	"library:read",
	"library:write",
]);

export type HyatusBrowserContext = {
	subject: string;
	email: string;
	name: string | null;
	scopes: ReadonlySet<Agent.AgentScope>;
	expiresAt: Date;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

export const isHyatusBrowserToken = (token: string) =>
	browserTokenPattern.test(token);

export async function requestHyatusBrowserContext({
	token,
	resource,
	fetcher = fetch,
}: {
	token: string;
	resource: string;
	fetcher?: typeof fetch;
}): Promise<HyatusBrowserContext | null> {
	if (!isHyatusBrowserToken(token)) return null;

	let response: Response;
	try {
		response = await fetcher(
			"https://auth.gptguest.com/v1/cap/browser/context",
			{
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
			},
		);
	} catch {
		return null;
	}
	if (!response.ok) return null;

	let payload: unknown;
	try {
		payload = await response.json();
	} catch {
		return null;
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
		return null;
	}

	const email = payload.user.email.trim().toLowerCase();
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;
	if (payload.user.name !== null && typeof payload.user.name !== "string") {
		return null;
	}
	const scopes = payload.scopes.filter(
		(scope): scope is Agent.AgentScope =>
			typeof scope === "string" && allowedScopes.has(scope as Agent.AgentScope),
	);
	if (
		scopes.length !== payload.scopes.length ||
		new Set(scopes).size !== scopes.length ||
		!scopes.includes("caps:read")
	) {
		return null;
	}
	const expiresAt = new Date(payload.expiresAt);
	if (
		!Number.isFinite(expiresAt.getTime()) ||
		expiresAt.getTime() <= Date.now() ||
		expiresAt.getTime() > Date.now() + 8 * 60 * 60 * 1_000
	) {
		return null;
	}

	return {
		subject: payload.user.id,
		email,
		name: payload.user.name?.trim() || null,
		scopes: new Set(scopes),
		expiresAt,
	};
}
