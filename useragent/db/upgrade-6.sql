UPDATE user SET name = user WHERE name IS NULL;

CREATE TABLE friend_group
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	name VARCHAR(20), 

	PRIMARY KEY(id),

	UNIQUE ( user_id, name )
);

INSERT INTO friend_group
( 
	user_id, 
	name
)
	SELECT id, 'friend' FROM user;

CREATE TABLE group_member
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	friend_group_id BIGINT,
	friend_claim_id BIGINT,

	PRIMARY KEY(id),

	UNIQUE ( friend_group_id, friend_claim_id )
);


INSERT INTO group_member 
(
	friend_group_id,
	friend_claim_id
)
	SELECT friend_group.id, friend_claim.id FROM user 
	JOIN friend_group ON user.id = friend_group.user_id
	JOIN friend_claim ON user.id = friend_claim.user_id ORDER BY user.user;

UPDATE friend_group SET name = 'social' WHERE name = 'friend';
