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
