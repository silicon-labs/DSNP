
DROP TABLE IF EXISTS user;
CREATE TABLE user
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	user VARCHAR(20), 
	pass_salt CHAR(24) BINARY,
	pass VARCHAR(40) BINARY, 

	user_keys_id BIGINT,
	identity_id BIGINT,
	relationship_id BIGINT,
	network_id BIGINT,

	PRIMARY KEY( id ),
	UNIQUE KEY ( user )
);

DROP TABLE IF EXISTS identity;
CREATE TABLE identity
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	iduri VARCHAR(128),
	hash VARCHAR(48) BINARY,

	PRIMARY KEY( id ),
	UNIQUE KEY ( iduri )
);

DROP TABLE IF EXISTS relationship;
CREATE TABLE relationship
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,

	-- 1: self.
	-- 8: friend.
	type SMALLINT,

	identity_id BIGINT,

	-- User's view of the remote identity. This is used for one's own data
	-- as well.
	name TEXT,
	email VARCHAR(50),

	PRIMARY KEY( id ),
	UNIQUE( user_id, identity_id )
);

DROP TABLE IF EXISTS friend_request;
CREATE TABLE friend_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,
	relationship_id BIGINT,

	accept_reqid VARCHAR(48) BINARY,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS sent_friend_request;
CREATE TABLE sent_friend_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,
	relationship_id BIGINT,

	user_notify_reqid VARCHAR(48) BINARY,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS friend_claim;
CREATE TABLE friend_claim
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,
	relationship_id BIGINT,

	PRIMARY KEY( id ),
	UNIQUE KEY ( user_id, identity_id )
);

DROP TABLE IF EXISTS network;
CREATE TABLE network
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,

	-- 1: primary.
	-- 2: friend group.
	type SMALLINT,

	-- Name visible to the user.
	private_name VARCHAR(20),

	-- Name distributed to others.
	dist_name VARCHAR(48) BINARY,

	key_gen BIGINT,

	PRIMARY KEY ( id )
);

--
-- Should have three tables:
--   published_owner: owner's view of what's published
--   published_friend: friend's view of what's published
--   activity_stream: what's going on with the user's friends.
--

DROP TABLE IF EXISTS activity;
CREATE TABLE activity
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	-- What is it?
	pub_type INT,

	-- The actors.
	user_id BIGINT,
	publisher_id BIGINT,
	author_id BIGINT,
	subject_id BIGINT,

	-- Supplied by the publisher.
	message_id VARCHAR(48),

	time_published TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	time_received TIMESTAMP DEFAULT 0,

	-- Pointers to material.
	remote_resource TEXT,
	remote_presentation TEXT,

	local_resource TEXT,
	local_presentation TEXT,
	local_thumbnail TEXT,

	message BLOB,

	PRIMARY KEY ( id ),

	-- The publishers are relationship_ids, which are all unique to each
	-- user, so we don't need to include user_id.
	UNIQUE KEY ( publisher_id, message_id )
);

DROP TABLE IF EXISTS image;
CREATE TABLE image
(
	user_id BIGINT,
	seq_num BIGINT NOT NULL AUTO_INCREMENT,

	rows INT,
	cols INT,
	mime_type VARCHAR(32),

	PRIMARY KEY ( user_id, seq_num )
);

DROP TABLE IF EXISTS remote_image;
CREATE TABLE remote_image
(
	user_id BIGINT,
	seq_num BIGINT NOT NULL AUTO_INCREMENT,

	PRIMARY KEY ( user_id, seq_num )
);


DROP TABLE IF EXISTS publication;
CREATE TABLE publication
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	message_id VARCHAR(64),

	user_id BIGINT,
	author_id BIGINT,
	subject_id BIGINT,

	publication_type INT,
	local_resource TEXT,
	local_presentation TEXT,

	time_published TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

	message BLOB,

	PRIMARY KEY ( id )
);

--
-- Database schema verison. Initialize it.
--
DROP TABLE IF EXISTS version;
CREATE TABLE version
(
	version INT
);

INSERT INTO version ( version ) VALUES ( 3 );
