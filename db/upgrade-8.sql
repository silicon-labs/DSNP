
ALTER TABLE user_ua ADD COLUMN type INT;
UPDATE user_ua SET type = 0;

CREATE TABLE wish
(
	friend_claim_id BIGINT,
	list TEXT,

	PRIMARY KEY( friend_claim_id )
);
