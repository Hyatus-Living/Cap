import type { CurrentUser } from "@cap/web-domain";

export const canMintPersistentCredential = (
	user: Pick<CurrentUser["Type"], "hyatusVerified">,
) => user.hyatusVerified !== true;
