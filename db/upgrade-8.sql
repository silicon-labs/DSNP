
ALTER TABLE user ADD COLUMN type INT;
UPDATE user SET type = 0;

CREATE TABLE wish
(
	friend_claim_id BIGINT,
	list TEXT,

	PRIMARY KEY( friend_claim_id )
);
