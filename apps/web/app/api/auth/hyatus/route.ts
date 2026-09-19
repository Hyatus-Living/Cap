import { serverEnv } from "@cap/env";
import { type NextRequest, NextResponse } from "next/server";
import { encode } from "next-auth/jwt";
import {
	createCodeChallenge,
	HYATUS_BROWSER_CLIENT_ID,
	HYATUS_BROWSER_INTENT_COOKIE,
	HYATUS_BROWSER_INTENT_MAX_AGE_SECONDS,
	HYATUS_BROWSER_INTENT_SALT,
	HYATUS_BROWSER_REDIRECT_URI,
	randomBase64Url,
	safeReturnPath,
} from "@/lib/hyatus-browser-auth";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
	const state = randomBase64Url();
	const codeVerifier = randomBase64Url();
	const intent = await encode({
		secret: serverEnv().NEXTAUTH_SECRET,
		salt: HYATUS_BROWSER_INTENT_SALT,
		maxAge: HYATUS_BROWSER_INTENT_MAX_AGE_SECONDS,
		token: {
			kind: "hyatus-cap-browser-intent",
			state,
			codeVerifier,
			returnTo: safeReturnPath(request.nextUrl.searchParams.get("returnTo")),
			issuedAt: Date.now(),
		},
	});
	const authorizeUrl = new URL(
		"https://auth.gptguest.com/v1/cap/browser/authorize",
	);
	authorizeUrl.searchParams.set("client_id", HYATUS_BROWSER_CLIENT_ID);
	authorizeUrl.searchParams.set("redirect_uri", HYATUS_BROWSER_REDIRECT_URI);
	authorizeUrl.searchParams.set("response_type", "code");
	authorizeUrl.searchParams.set(
		"code_challenge",
		createCodeChallenge(codeVerifier),
	);
	authorizeUrl.searchParams.set("code_challenge_method", "S256");
	authorizeUrl.searchParams.set("state", state);

	const response = NextResponse.redirect(authorizeUrl);
	response.headers.set("Cache-Control", "private, no-store");
	response.cookies.set(HYATUS_BROWSER_INTENT_COOKIE, intent, {
		httpOnly: true,
		secure: true,
		sameSite: "lax",
		path: "/api/auth/hyatus",
		maxAge: HYATUS_BROWSER_INTENT_MAX_AGE_SECONDS,
	});
	return response;
}
