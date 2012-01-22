-- Users and Identities
--

DROP TABLE IF EXISTS site;
CREATE TABLE site
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	site VARCHAR(128),

	PRIMARY KEY( id ),
	UNIQUE KEY ( site )
);

DROP TABLE IF EXISTS user;
CREATE TABLE user
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	iduri VARCHAR(128),

	site_id BIGINT,
	identity_id BIGINT,
	network_id BIGINT,

	PRIMARY KEY( id ),
	UNIQUE KEY ( iduri )
);

DROP TABLE IF EXISTS identity;
CREATE TABLE identity
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	iduri VARCHAR(128),
	hash VARCHAR(48) BINARY,
	public_keys BOOLEAN,

	PRIMARY KEY( id ),
	UNIQUE KEY ( iduri )
);

--
-- Friendship Request
--

DROP TABLE IF EXISTS relid_request;
CREATE TABLE relid_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	requested_reqid VARCHAR(48) BINARY,

	requested_relid_set BLOB,
	message BLOB,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS relid_response;
CREATE TABLE relid_response
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	identity_id BIGINT,

	requested_reqid VARCHAR(48) BINARY,
	response_reqid VARCHAR(48) BINARY,

	message BLOB,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS friend_request;
CREATE TABLE friend_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	-- User agent uses this to identify the request.
	accept_reqid VARCHAR(48) BINARY,
	peer_notify_reqid VARCHAR(48) BINARY,

	relid_set_pair BLOB,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS sent_friend_request;
CREATE TABLE sent_friend_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	peer_notify_reqid VARCHAR(48) BINARY,
	user_notify_reqid VARCHAR(48) BINARY,

	relid_set_pair BLOB,

	PRIMARY KEY( id )
);

--
-- Established and Soon-to-be Established Friendship Claims
--

DROP TABLE IF EXISTS friend_claim;
CREATE TABLE friend_claim
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	state INT,

	PRIMARY KEY( id ),
	UNIQUE KEY ( user_id, identity_id )
);

--
-- Relationship Ids
--

DROP TABLE IF EXISTS put_relid;
CREATE TABLE put_relid
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,
	friend_claim_id BIGINT,

	key_priv INT,
	put_relid VARCHAR(48) BINARY,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS get_relid;
CREATE TABLE get_relid
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,
	friend_claim_id BIGINT,

	key_priv INT,
	get_relid VARCHAR(48) BINARY,

	PRIMARY KEY( id )
);

--
-- In and Out Broadcast Keys
--

DROP TABLE IF EXISTS put_broadcast_key;
CREATE TABLE put_broadcast_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	network_id BIGINT,
	generation BIGINT,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS get_broadcast_key;
CREATE TABLE get_broadcast_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	friend_claim_id BIGINT,
	network_dist VARCHAR(48) BINARY,
	generation BIGINT,

	PRIMARY KEY ( id ),
	UNIQUE KEY ( friend_claim_id, network_dist, generation )
);

DROP TABLE IF EXISTS rb_key;
CREATE TABLE rb_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	friend_claim_id BIGINT,
	actor_identity_id BIGINT,

	hash VARCHAR(48) BINARY,

	PRIMARY KEY ( id ),

	UNIQUE KEY ( friend_claim_id, actor_identity_id )
);

--
-- Network Management
--

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

--
-- Friend Login
--

DROP TABLE IF EXISTS ftoken_request;
CREATE TABLE ftoken_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	token VARCHAR(48) BINARY,
	reqid VARCHAR(48) BINARY,
	message BLOB,
	network_id BIGINT,

	PRIMARY KEY( id )
);


--
-- Login and Friend Login Tokens
--

DROP TABLE IF EXISTS login_token;
CREATE TABLE login_token
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,

	login_token VARCHAR(48) BINARY,
	session_id VARCHAR(48) BINARY,
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
	session_id VARCHAR(48) BINARY,
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

--
-- Remote Broadcast
--

DROP TABLE IF EXISTS remote_broadcast_request;
CREATE TABLE remote_broadcast_request
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	identity_id BIGINT,

	state INT,

	author_reqid VARCHAR(48) BINARY,
	reqid_final VARCHAR(48) BINARY,

	message_id VARCHAR(64) BINARY,
	plain_message BLOB,
	enc_message BLOB,

	UNIQUE( message_id ),
	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS rb_request_actor;
CREATE TABLE rb_request_actor
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	remote_broadcast_request_id BIGINT,
	state INT,
	actor_type INT,
	identity_id BIGINT,

	return_reqid VARCHAR(48) BINARY,
	enc_message BLOB,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS remote_broadcast_response;
CREATE TABLE remote_broadcast_response
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	publisher_id BIGINT,

	state INT,

	reqid VARCHAR(48) BINARY,
	return_reqid VARCHAR(48) BINARY,
	message_id VARCHAR(64) BINARY,

	plain_message BLOB,
	enc_message BLOB,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS rb_response_actor;
CREATE TABLE rb_response_actor
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	remote_broadcast_response_id BIGINT,
	actor_type INT,
	identity_id BIGINT,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS remote_broadcast_subject;
CREATE TABLE remote_broadcast_subject
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	publisher_id BIGINT,

	state INT,

	reqid VARCHAR(48) BINARY,
	return_reqid VARCHAR(48) BINARY,
	message_id VARCHAR(64) BINARY,

	plain_message BLOB,
	enc_message BLOB,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS rb_subject_actor;
CREATE TABLE rb_subject_actor
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	remote_broadcast_subject_id BIGINT,
	actor_type INT,
	identity_id BIGINT,

	PRIMARY KEY ( id )
);

--
-- Direct Message Queue
--

DROP TABLE IF EXISTS message_queue;
CREATE TABLE message_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	host TEXT,
	relid VARCHAR(48) BINARY,
	send_after DATETIME,

	message BLOB,

	PRIMARY KEY ( id )
);

--
-- Friend-of-a-Friend Message Queue
--

DROP TABLE IF EXISTS fetch_rb_key_queue;
CREATE TABLE fetch_rb_key_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	host TEXT,
	relid VARCHAR(48) BINARY,

	get_broadcast_key_id BIGINT,
	friend_claim_id BIGINT,
	actor_identity_id BIGINT,

	send_after DATETIME,

	message BLOB,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS rb_key_response;
CREATE TABLE rb_key_response
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	friend_claim_id BIGINT,
	actor_identity_id BIGINT,
	message BLOB,

	PRIMARY KEY ( id )
);

--
-- Broadcast Queue
--

DROP TABLE IF EXISTS broadcast_message;
CREATE TABLE broadcast_message
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	dist_name TEXT,
	key_gen BIGINT,
	message BLOB,
	
	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS broadcast_queue;
CREATE TABLE broadcast_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	broadcast_message_id BIGINT,
	host TEXT,
	send_after DATETIME,

	PRIMARY KEY ( id )
);


DROP TABLE IF EXISTS broadcast_recipient;
CREATE TABLE broadcast_recipient
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	broadcast_queue_id BIGINT,
	relid VARCHAR(48) BINARY,

	PRIMARY KEY ( id )
);

--
-- Broadcast Messages we received but had to delay processing of.
--
DROP TABLE IF EXISTS received_broadcast;
CREATE TABLE received_broadcast
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	relid VARCHAR(48) BINARY,
	dist_name VARCHAR(48) BINARY,
	generation BIGINT,
	message BLOB,

	reprocess BOOLEAN, 

	process_after DATETIME,

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
