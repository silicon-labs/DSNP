
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
	JOIN friend_claim ON user.user = friend_claim.user ORDER BY user.user;


-- state 1: out of tree
-- state 2: in tree

ALTER TABLE put_tree ADD COLUMN state INT;

ALTER TABLE user CHANGE COLUMN put_generation key_gen BIGINT;
ALTER TABLE user ADD COLUMN tree_gen_low BIGINT;
ALTER TABLE user ADD COLUMN tree_gen_high BIGINT;

-- Reset the broadcast key generations.
UPDATE get_broadcast_key SET generation = 1;
UPDATE put_broadcast_key SET generation = 1;

-- Reset the tree.s
DELETE FROM put_tree;
DELETE FROM get_tree;

INSERT INTO put_tree
( 
	friend_claim_id, 
	generation,
	root, 
	active, 
	state
)
	SELECT id, 1, false, true, 1
	FROM friend_claim 

UPDATE user SET key_gen = 1, tree_gen_low = 1, tree_gen_high = 1

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

ALTER TABLE user ADD UNIQUE ( user );
