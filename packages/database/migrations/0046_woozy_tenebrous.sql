CREATE TABLE `hyatus_cap_identities` (
	`id` varchar(15) NOT NULL,
	`hyatusSubject` varchar(255) NOT NULL,
	`userId` varchar(15) NOT NULL,
	`emailAtLink` varchar(255) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `hyatus_cap_identities_id` PRIMARY KEY(`id`),
	CONSTRAINT `hyatus_cap_subject_idx` UNIQUE(`hyatusSubject`),
	CONSTRAINT `hyatus_cap_user_id_idx` UNIQUE(`userId`)
);
