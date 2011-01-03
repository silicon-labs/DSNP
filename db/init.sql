
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

-- Public and Private keys for users.
DROP TABLE IF EXISTS user_keys;
CREATE TABLE user_keys
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	rsa_n TEXT BINARY,
	rsa_e TEXT BINARY,
	rsa_d TEXT BINARY,
	rsa_p TEXT BINARY,
	rsa_q TEXT BINARY,
	rsa_dmp1 TEXT BINARY,
	rsa_dmq1 TEXT BINARY,
	rsa_iqmp TEXT BINARY,

	PRIMARY KEY( id )
);

-- Fetched public keys.
DROP TABLE IF EXISTS public_key;
CREATE TABLE public_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	identity_id BIGINT,
	rsa_n TEXT,
	rsa_e TEXT,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS relid_request;
CREATE TABLE relid_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	requested_relid VARCHAR(48) BINARY,
	reqid VARCHAR(48) BINARY,
	msg_sym TEXT,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS relid_response;
CREATE TABLE relid_response
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	identity_id BIGINT,

	requested_relid VARCHAR(48) BINARY,
	returned_relid VARCHAR(48) BINARY,
	reqid VARCHAR(48) BINARY,
	msg_sym TEXT,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS friend_request;
CREATE TABLE friend_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,
	relationship_id BIGINT,

	reqid VARCHAR(48) BINARY,
	requested_relid VARCHAR(48) BINARY,
	returned_relid VARCHAR(48) BINARY,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS sent_friend_request;
CREATE TABLE sent_friend_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,
	relationship_id BIGINT,

	requested_relid VARCHAR(48) BINARY,
	returned_relid VARCHAR(48) BINARY,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS friend_claim;
CREATE TABLE friend_claim
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,
	relationship_id BIGINT,

	put_relid VARCHAR(48) BINARY,
	get_relid VARCHAR(48) BINARY,

	PRIMARY KEY( id ),
	UNIQUE KEY ( user_id, identity_id )
);

DROP TABLE IF EXISTS ftoken_request;
CREATE TABLE ftoken_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	token VARCHAR(48) BINARY,
	reqid VARCHAR(48) BINARY,
	msg_sym TEXT,
	network_id BIGINT,

	PRIMARY KEY( id )
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

DROP TABLE IF EXISTS network_member;
CREATE TABLE network_member
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	network_id BIGINT,
	friend_claim_id BIGINT,

	PRIMARY KEY ( id ),
	UNIQUE KEY ( network_id, friend_claim_id )
);


DROP TABLE IF EXISTS broadcast_message;
CREATE TABLE broadcast_message
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	dist_name TEXT,
	key_gen BIGINT,
	message TEXT,
	
	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS broadcast_queue;
CREATE TABLE broadcast_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	message_id BIGINT,
	send_after DATETIME,
	to_site TEXT,
	forward BOOLEAN,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS broadcast_recipient;
CREATE TABLE broadcast_recipient
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	queue_id BIGINT,
	relid VARCHAR(48) BINARY,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS message_queue;
CREATE TABLE message_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	send_after DATETIME,

	relid VARCHAR(48) BINARY,
	message TEXT,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS broadcasted;
CREATE TABLE broadcasted
(
	user_id BIGINT,

	author_id BIGINT,
	subject_id BIGINT,

	seq_num BIGINT NOT NULL AUTO_INCREMENT,
	time_published TIMESTAMP,
	type CHAR(4),
	message BLOB,

	PRIMARY KEY ( user_id, seq_num )
);

DROP TABLE IF EXISTS login_token;
CREATE TABLE login_token
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,

	login_token VARCHAR(48) BINARY,
	expires TIMESTAMP,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS flogin_token;
CREATE TABLE flogin_token
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	login_token VARCHAR(48) BINARY,
	expires TIMESTAMP,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS remote_flogin_token;
CREATE TABLE remote_flogin_token
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	login_token VARCHAR(48) BINARY,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS pending_remote_broadcast;
CREATE TABLE pending_remote_broadcast
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	hash TEXT,
	reqid VARCHAR(48) BINARY,
	reqid_final VARCHAR(48) BINARY,
	seq_num BIGINT,
	generation BIGINT,
	sym TEXT,
	network_name TEXT,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS remote_broadcast_request;
CREATE TABLE remote_broadcast_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	reqid VARCHAR(48) BINARY,
	generation BIGINT,
	sym TEXT,

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

	user_id BIGINT,
	author_id BIGINT,
	subject_id BIGINT,
	published BOOL,
	seq_num BIGINT,
	type CHAR(4),
	remote_resid BIGINT,
	message BLOB,
	local_resid BIGINT,
	time_published TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	time_received TIMESTAMP DEFAULT 0,
	network_id BIGINT,

	PRIMARY KEY ( id )
);


--
-- END ACTIVITY
--

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

DROP TABLE IF EXISTS put_broadcast_key;
CREATE TABLE put_broadcast_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	network_id BIGINT,

	generation BIGINT,
	broadcast_key VARCHAR(48) BINARY,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS get_broadcast_key;
CREATE TABLE get_broadcast_key
(
	id bigint NOT NULL AUTO_INCREMENT,

	friend_claim_id BIGINT,
	network_dist VARCHAR(48) BINARY,
	generation BIGINT,

	broadcast_key VARCHAR(48) BINARY,

	PRIMARY KEY ( id ),
	UNIQUE KEY ( friend_claim_id, network_dist, generation )
);

-- Database schema verison. Initialize it.
DROP TABLE IF EXISTS version;
CREATE TABLE version
(
	version INT
);

INSERT INTO version ( version ) VALUES ( 0 );


