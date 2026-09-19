import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const HYATUS_BROWSER_CLIENT_ID = "hyatus-cap-web";
export const HYATUS_BROWSER_REDIRECT_URI =
	"https://videos.gptguest.com/api/auth/hyatus/callback";
export const HYATUS_BROWSER_INTENT_COOKIE = "hyatus-cap.browser-intent";
export const HYATUS_BROWSER_INTENT_SALT = "hyatus-cap-browser-intent";
export const HYATUS_BROWSER_MAX_AGE_SECONDS = 8 * 60 * 60;
export const HYATUS_BROWSER_INTENT_MAX_AGE_SECONDS = 10 * 60;

export type HyatusBrowserIntent = {
	kind: "hyatus-cap-browser-intent";
	state: string;
	codeVerifier: string;
	returnTo: string;
	issuedAt: number;
};

export const randomBase64Url = () => randomBytes(32).toString("base64url");

export const createCodeChallenge = (verifier: string) =>
	createHash("sha256").update(verifier).digest("base64url");

export const isHyatusBrowserUser = (user: { hyatusVerified?: boolean }) =>
	user.hyatusVerified === true;

export const safeReturnPath = (value: string | null | undefined) => {
	if (!value || !value.startsWith("/") || value.startsWith("//")) {
		return "/dashboard/caps";
	}
	try {
		const parsed = new URL(value, "https://videos.gptguest.com");
		return parsed.origin === "https://videos.gptguest.com"
			? `${parsed.pathname}${parsed.search}${parsed.hash}`
			: "/dashboard/caps";
	} catch {
		return "/dashboard/caps";
	}
};

export const validIntent = (
	value: unknown,
	state: string,
	now = Date.now(),
): value is HyatusBrowserIntent => {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const intent = value as Partial<HyatusBrowserIntent>;
	if (
		intent.kind !== "hyatus-cap-browser-intent" ||
		typeof intent.state !== "string" ||
		typeof intent.codeVerifier !== "string" ||
		typeof intent.returnTo !== "string" ||
		typeof intent.issuedAt !== "number" ||
		intent.state.length !== 43 ||
		intent.codeVerifier.length !== 43 ||
		state.length !== 43 ||
		now - intent.issuedAt >= HYATUS_BROWSER_INTENT_MAX_AGE_SECONDS * 1_000 ||
		intent.issuedAt > now + 30_000
	) {
		return false;
	}
	return timingSafeEqual(Buffer.from(intent.state), Buffer.from(state));
};
