ALTER TABLE user ADD COLUMN identity TEXT;
ALTER TABLE user ADD COLUMN name VARCHAR(50);
ALTER TABLE user ADD COLUMN email VARCHAR(50);
ALTER TABLE user ADD COLUMN type INT;

UPDATE user, user_ua 
SET 
	user.identity = user_ua.identity,
	user.name = user_ua.name,
	user.email = user_ua.email,
	user.type = user_ua.type
WHERE user.user = user_ua.user;

DROP TABLE user_ua;

ALTER TABLE friend_claim ADD COLUMN user_id BIGINT;
ALTER TABLE friend_claim ADD COLUMN identity TEXT;
ALTER TABLE friend_claim ADD COLUMN name TEXT;
ALTER TABLE friend_claim ADD COLUMN state INT;

UPDATE friend_claim, friend_claim_ua, user
SET 
	friend_claim.user_id = user.id,
	friend_claim.identity = friend_claim.friend_id,
	friend_claim.name = friend_claim.friend_id,
	friend_claim.state = 0
WHERE friend_claim.user = user.user;

DROP TABLE friend_claim_ua;

DROP TABLE friend_request_ua;
DROP TABLE sent_friend_request_ua;
DROP TABLE friend_group_ua;
DROP TABLE group_member_ua;
