UPDATE user_ua SET name = user WHERE name IS NULL;

CREATE TABLE friend_group_ua
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	name VARCHAR(20), 

	PRIMARY KEY(id),

	UNIQUE ( user_id, name )
);

INSERT INTO friend_group_ua
( 
	user_id, 
	name
)
	SELECT id, 'friend' FROM user_ua;

CREATE TABLE group_member_ua
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	friend_group_id BIGINT,
	friend_claim_id BIGINT,

	PRIMARY KEY(id),

	UNIQUE ( friend_group_id, friend_claim_id )
);


INSERT INTO group_member_ua 
(
	friend_group_id,
	friend_claim_id
)
	SELECT friend_group_ua.id, friend_claim_ua.id FROM user_ua 
	JOIN friend_group_ua ON user_ua.id = friend_group_ua.user_id
	JOIN friend_claim_ua ON user_ua.id = friend_claim_ua.user_id ORDER BY user_ua.user;

UPDATE friend_group_ua SET name = 'social' WHERE name = 'friend';
