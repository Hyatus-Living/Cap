import { db } from "@cap/database";
import { requestHyatusBrowserContext } from "@cap/database/auth/hyatus-browser";
import { users } from "@cap/database/schema";
import { serverEnv } from "@cap/env";
import { resolveHyatusCapIdentityWithDb } from "@cap/web-backend";
import { eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";
import { decode, encode } from "next-auth/jwt";
import {
	HYATUS_BROWSER_CLIENT_ID,
	HYATUS_BROWSER_INTENT_COOKIE,
	HYATUS_BROWSER_INTENT_SALT,
	HYATUS_BROWSER_MAX_AGE_SECONDS,
	HYATUS_BROWSER_REDIRECT_URI,
	safeReturnPath,
	validIntent,
} from "@/lib/hyatus-browser-auth";

export const dynamic = "force-dynamic";

const sessionCookieName = "next-auth.session-token";

const errorResponse = (request: NextRequest, error: string) => {
	const target = new URL("/login", request.url);
	target.searchParams.set("error", error);
	const response = NextResponse.redirect(target);
	response.cookies.set(HYATUS_BROWSER_INTENT_COOKIE, "", {
		httpOnly: true,
		secure: true,
		sameSite: "lax",
		path: "/api/auth/hyatus",
		maxAge: 0,
	});
	return response;
};

export async function GET(request: NextRequest) {
	const code = request.nextUrl.searchParams.get("code");
	const state = request.nextUrl.searchParams.get("state");
	const encodedIntent = request.cookies.get(
		HYATUS_BROWSER_INTENT_COOKIE,
	)?.value;
	if (!code || !state || !encodedIntent) {
		return errorResponse(request, "HyatusSessionExpired");
	}

	let intent: Awaited<ReturnType<typeof decode>>;
	try {
		intent = await decode({
			token: encodedIntent,
			secret: serverEnv().NEXTAUTH_SECRET,
			salt: HYATUS_BROWSER_INTENT_SALT,
		});
	} catch {
		return errorResponse(request, "HyatusSessionExpired");
	}
	if (!validIntent(intent, state)) {
		return errorResponse(request, "HyatusSessionExpired");
	}

	let tokenResponse: Response;
	try {
		tokenResponse = await fetch(
			"https://auth.gptguest.com/v1/cap/browser/token",
			{
				method: "POST",
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					"Cache-Control": "no-store",
				},
				body: JSON.stringify({
					grant_type: "authorization_code",
					client_id: HYATUS_BROWSER_CLIENT_ID,
					redirect_uri: HYATUS_BROWSER_REDIRECT_URI,
					code,
					code_verifier: intent.codeVerifier,
				}),
				cache: "no-store",
				credentials: "omit",
				redirect: "error",
				signal: AbortSignal.timeout(3_000),
			},
		);
	} catch {
		return errorResponse(request, "HyatusSignInFailed");
	}
	if (!tokenResponse.ok) {
		return errorResponse(request, "HyatusSignInFailed");
	}
	let payload: Record<string, unknown>;
	try {
		const value: unknown = await tokenResponse.json();
		if (!value || typeof value !== "object" || Array.isArray(value)) {
			return errorResponse(request, "HyatusSignInFailed");
		}
		payload = value as Record<string, unknown>;
	} catch {
		return errorResponse(request, "HyatusSignInFailed");
	}
	if (
		typeof payload.accessToken !== "string" ||
		payload.tokenType !== "Bearer" ||
		payload.resource !== "https://videos.gptguest.com" ||
		!Array.isArray(payload.scopes) ||
		!payload.scopes.every((scope) => typeof scope === "string") ||
		typeof payload.expiresAt !== "string"
	) {
		return errorResponse(request, "HyatusSignInFailed");
	}
	const tokenExpiresAt = new Date(payload.expiresAt);
	if (
		!Number.isFinite(tokenExpiresAt.getTime()) ||
		tokenExpiresAt.getTime() <= Date.now() ||
		tokenExpiresAt.getTime() >
			Date.now() + HYATUS_BROWSER_MAX_AGE_SECONDS * 1_000
	) {
		return errorResponse(request, "HyatusSignInFailed");
	}
	const context = await requestHyatusBrowserContext({
		token: payload.accessToken,
		resource: "https://videos.gptguest.com",
	});
	if (!context) return errorResponse(request, "HyatusSignInFailed");
	const tokenScopes = new Set(payload.scopes as string[]);
	if (
		tokenScopes.size !== payload.scopes.length ||
		tokenScopes.size !== context.scopes.size ||
		![...context.scopes].every((scope) => tokenScopes.has(scope))
	) {
		return errorResponse(request, "HyatusSignInFailed");
	}

	const resolved = await resolveHyatusCapIdentityWithDb(db(), {
		...context,
		scopes: new Set(context.scopes),
	});
	if (resolved.state === "link_required") {
		return errorResponse(request, "HyatusLinkRequired");
	}
	if (resolved.state !== "resolved") {
		return errorResponse(request, "HyatusSignInFailed");
	}
	const [user] = await db()
		.select({
			id: users.id,
			name: users.name,
			lastName: users.lastName,
			email: users.email,
			image: users.image,
			authSessionVersion: users.authSessionVersion,
		})
		.from(users)
		.where(eq(users.id, resolved.user.id))
		.limit(1);
	if (!user) return errorResponse(request, "HyatusSignInFailed");

	const expiresAt = new Date(
		Math.min(tokenExpiresAt.getTime(), context.expiresAt.getTime()),
	);
	const maxAge = Math.min(
		HYATUS_BROWSER_MAX_AGE_SECONDS,
		Math.max(1, Math.floor((expiresAt.getTime() - Date.now()) / 1_000)),
	);
	const sessionToken = await encode({
		secret: serverEnv().NEXTAUTH_SECRET,
		maxAge,
		token: {
			id: user.id,
			name: user.name,
			lastName: user.lastName,
			email: user.email,
			picture: user.image,
			sessionVersion: user.authSessionVersion,
			hyatusBrowserAccessToken: payload.accessToken,
			hyatusSubject: context.subject,
			hyatusScopes: [...context.scopes],
			hyatusVerified: true,
		},
	});
	const response = NextResponse.redirect(
		new URL(safeReturnPath(intent.returnTo), request.url),
	);
	response.headers.set("Cache-Control", "private, no-store");
	response.cookies.set(sessionCookieName, sessionToken, {
		httpOnly: true,
		secure: true,
		sameSite: "lax",
		path: "/",
		maxAge,
	});
	response.cookies.set(HYATUS_BROWSER_INTENT_COOKIE, "", {
		httpOnly: true,
		secure: true,
		sameSite: "lax",
		path: "/api/auth/hyatus",
		maxAge: 0,
	});
	return response;
}
