
ALTER TABLE friend_claim ADD COLUMN type INTEGER;

-- 1 is self
-- 8 active friend
UPDATE friend_claim SET type = 8;

INSERT INTO friend_claim 
	( user, user_id, friend_id, name, type )
	( SELECT user, id, identity, name, 1 FROM user );
