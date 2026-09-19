import { User } from "@cap/web-domain";
import { eq, type InferSelectModel } from "drizzle-orm";
import { getServerSession } from "next-auth";
import { cache } from "react";
import { db } from "../";
import { users } from "../schema";
import { authOptions } from "./auth-options";

export const getSession = async () => {
	const session = await getServerSession(authOptions());

	return session;
};

export const getCurrentUser = cache(
	async (): Promise<
		| (InferSelectModel<typeof users> & {
				hyatusVerified?: boolean;
				hyatusScopes?: ReadonlySet<string>;
		  })
		| null
	> => {
		const session = await getServerSession(authOptions());

		if (!session) return null;

		const [currentUser] = await db()
			.select()
			.from(users)
			.where(eq(users.id, User.UserId.make(session.user.id)));

		return currentUser
			? {
					...currentUser,
					hyatusVerified: session.user.hyatusVerified === true,
					hyatusScopes: new Set(session.user.hyatusScopes ?? []),
				}
			: null;
	},
);

export const userSelectProps = users.$inferSelect;
