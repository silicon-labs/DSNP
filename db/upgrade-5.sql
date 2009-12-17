
CREATE TABLE friend_group
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	name VARCHAR(20), 

	PRIMARY KEY(id),

	UNIQUE ( user_id, name )
);

CREATE TABLE group_member
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	friend_group_id BIGINT,
	friend_claim_id BIGINT,

	PRIMARY KEY(id),

	UNIQUE ( friend_group_id, friend_claim_id )
);
