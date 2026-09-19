import type { User } from "next-auth";

type UserId = string;

declare module "next-auth/jwt" {
	interface JWT {
		id: UserId;
		hyatusBrowserAccessToken?: string;
		hyatusSubject?: string;
		hyatusScopes?: string[];
		hyatusVerified?: boolean;
	}
}

declare module "next-auth" {
	interface Session {
		user: User & {
			id: UserId;
			hyatusScopes?: string[];
			hyatusVerified?: boolean;
		};
	}
}
