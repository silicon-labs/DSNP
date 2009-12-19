
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

-- state 1: out of tree
-- state 2: in tree

ALTER TABLE put_tree ADD COLUMN state INT;
update put_tree set state = 2;

ALTER TABLE user CHANGE COLUMN put_generation key_gen BIGINT;
ALTER TABLE user ADD COLUMN tree_gen_low BIGINT;
ALTER TABLE user ADD COLUMN tree_gen_high BIGINT;
UPDATE user SET tree_gen_low = 0;
UPDATE user SET tree_gen_high = key_gen;


DROP TABLE broadcast_queue;
CREATE TABLE broadcast_message
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	key_gen BIGINT,
	tree_gen_low BIGINT,
	tree_gen_high BIGINT,
	message TEXT,
	
	PRIMARY KEY(id)
);

CREATE TABLE broadcast_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	message_id BIGINT,
	send_after DATETIME,
	to_site TEXT,
	forward BOOLEAN,

	PRIMARY KEY(id)
);

CREATE TABLE broadcast_recipient
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	queue_id BIGINT,
	relid VARCHAR(48),

	PRIMARY KEY(id)
);
