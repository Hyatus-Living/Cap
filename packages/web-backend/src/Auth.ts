import { getServerSession } from "@cap/database/auth/auth-options";
import { isBlockedAccountEmail } from "@cap/database/auth/domain-utils";
import * as Db from "@cap/database/schema";
import {
	type Agent,
	CurrentUser,
	type DatabaseError,
	HttpAuthMiddleware,
	UserId,
} from "@cap/web-domain";
import { HttpApiError, HttpServerRequest } from "@effect/platform";
import * as Dz from "drizzle-orm";
import { type Cause, Effect, Layer, Option, Schema } from "effect";

import { Database } from "./Database.ts";

type AuthenticatedDatabaseUser = typeof Db.users.$inferSelect & {
	hyatusVerified?: boolean;
	hyatusScopes?: ReadonlySet<string>;
};

export const getCurrentUser = Effect.gen(function* () {
	const db = yield* Database;
	const session = yield* Effect.tryPromise(() => getServerSession());
	if (!session?.user) return Option.none();

	const sessionUser = session.user as typeof session.user & {
		id: string;
		hyatusScopes?: string[];
		hyatusVerified?: boolean;
	};
	const [currentUser] = yield* db.use((db) =>
		db
			.select()
			.from(Db.users)
			.where(Dz.eq(Db.users.id, UserId.make(sessionUser.id))),
	);

	return Option.fromNullable(
		currentUser
			? {
					...currentUser,
					hyatusVerified: sessionUser.hyatusVerified === true,
					hyatusScopes: new Set<string>(sessionUser.hyatusScopes ?? []),
				}
			: null,
	);
}).pipe(Effect.withSpan("getCurrentUser"));

export const makeCurrentUser = (user: AuthenticatedDatabaseUser) =>
	CurrentUser.of({
		id: user.id,
		email: user.email,
		activeOrganizationId: user.activeOrganizationId,
		iconUrlOrKey: Option.fromNullable(user.image),
		hyatusVerified: user.hyatusVerified === true,
		hyatusScopes: new Set(
			[...(user.hyatusScopes ?? [])].filter(
				(scope): scope is Agent.AgentScope => typeof scope === "string",
			),
		),
	});

export const makeCurrentUserLayer = (user: AuthenticatedDatabaseUser) =>
	Layer.succeed(CurrentUser, makeCurrentUser(user));

export const HttpAuthMiddlewareLive = Layer.effect(
	HttpAuthMiddleware,
	Effect.gen(function* () {
		const database = yield* Database;

		return HttpAuthMiddleware.of(
			Effect.gen(function* () {
				const headers = yield* HttpServerRequest.schemaHeaders(
					Schema.Struct({ authorization: Schema.optional(Schema.String) }),
				);
				const authHeader = headers.authorization?.split(" ")[1];

				let user: Option.Option<AuthenticatedDatabaseUser>;

				if (authHeader?.length === 36) {
					user = yield* database
						.use((db) =>
							db
								.select()
								.from(Db.users)
								.leftJoin(
									Db.authApiKeys,
									Dz.eq(Db.users.id, Db.authApiKeys.userId),
								)
								.where(Dz.eq(Db.authApiKeys.id, authHeader)),
						)
						.pipe(
							Effect.map(([entry]) =>
								Option.fromNullable(entry?.users).pipe(
									Option.filter((user) => !isBlockedAccountEmail(user.email)),
								),
							),
						);
				} else {
					user = yield* getCurrentUser;
				}

				return yield* user.pipe(
					Option.map(makeCurrentUser),
					Effect.catchTag("NoSuchElementException", () =>
						Effect.fail(new HttpApiError.Unauthorized()),
					),
				);
			}).pipe(
				Effect.provideService(Database, database),
				Effect.catchTags({
					UnknownException: () =>
						Effect.fail(new HttpApiError.InternalServerError()),
					DatabaseError: () =>
						Effect.fail(new HttpApiError.InternalServerError()),
					ParseError: () => Effect.fail(new HttpApiError.BadRequest()),
				}),
			),
		);
	}),
);

export const provideOptionalAuth = <A, E, R>(
	app: Effect.Effect<A, E, R>,
): Effect.Effect<A, E | DatabaseError | Cause.UnknownException, R | Database> =>
	Effect.gen(function* () {
		const user = yield* getCurrentUser;

		return yield* user.pipe(
			Option.match({
				onNone: () => app,
				onSome: (user) => app.pipe(Effect.provide(makeCurrentUserLayer(user))),
			}),
		);
	});
