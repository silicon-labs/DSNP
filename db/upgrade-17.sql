CREATE TABLE network_name
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	name TEXT,

	PRIMARY KEY(id)
);

INSERT INTO network_name ( name ) VALUES ( 'social' );
INSERT INTO network_name ( name ) VALUES ( 'work' );
INSERT INTO network_name ( name ) VALUES ( 'professional' );
INSERT INTO network_name ( name ) VALUES ( 'family' );
INSERT INTO network_name ( name ) VALUES ( 'school' );

DROP TABLE friend_group;
CREATE TABLE network
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	network_name_id BIGINT,

	key_gen BIGINT,
	tree_gen_low BIGINT,
	tree_gen_high BIGINT,

	PRIMARY KEY ( id ),

	UNIQUE ( user_id, network_name_id )
);

DROP TABLE group_member;
CREATE TABLE network_member
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	network_id BIGINT,
	friend_claim_id BIGINT,

	PRIMARY KEY ( id ),

	UNIQUE ( network_id, friend_claim_id )
);

DROP TABLE put_broadcast_key;
CREATE TABLE put_broadcast_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	network_id BIGINT,

	generation BIGINT,
	broadcast_key VARCHAR(48),

	PRIMARY KEY ( id )
);

DROP TABLE put_tree;
CREATE TABLE put_tree
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	network_id BIGINT,
	friend_claim_id BIGINT,

	generation BIGINT,
	root BOOLEAN,
	forward1 TEXT,
	forward2 TEXT,
	active BOOLEAN,
	state INT,

	PRIMARY KEY ( id )
);

DROP TABLE friend_link;
CREATE TABLE friend_link
(
	network_id BIGINT,
	from_fcid BIGINT,
	to_fcid BIGINT,

	PRIMARY KEY ( network_id, from_fcid, to_fcid )
);

DROP TABLE get_broadcast_key;
CREATE TABLE get_broadcast_key
(
	id bigint NOT NULL AUTO_INCREMENT,

	friend_claim_id BIGINT,
	network_id BIGINT,
	generation BIGINT,

	broadcast_key VARCHAR(48),
	friend_proof TEXT,
	reverse_proof TEXT,

	UNIQUE KEY ( network_id, friend_claim_id, generation ),
	PRIMARY KEY (id)
);

/*!40101 SET character_set_client = @saved_cs_client */;

-- ALTER TABLE get_tree ADD COLUMN network_id BIGINT;
--UPDATE get_tree, network 
--	SET get_tree.network_id = network.id
--	WHERE get_tree.group_name = network.name;
--
--ALTER TABLE broadcast_message ADD COLUMN network_id BIGINT;
--UPDATE broadcast_message, network 
--	SET broadcast_message.network_id = network.id
--	WHERE broadcast_message.group_name = network.name;
--
--ALTER TABLE pending_remote_broadcast ADD COLUMN network_id BIGINT;
--UPDATE pending_remote_broadcast, network 
--	SET pending_remote_broadcast.network_id = network.id
--	WHERE pending_remote_broadcast.group_name = network.name;
