
CREATE TABLE user
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	user VARCHAR(20), 
	pass_salt CHAR(24) BINARY,
	pass VARCHAR(40) BINARY, 

	identity_id BIGINT,
	user_keys_id BIGINT,
	primary_network_id BIGINT,

	PRIMARY KEY( id ),
	UNIQUE KEY ( user )
);

CREATE TABLE identity
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	iduri VARCHAR(128),
	hash VARCHAR(48) BINARY,

	PRIMARY KEY( id ),
	UNIQUE KEY ( iduri )
);

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

	PRIMARY KEY( id )
);

-- Public and Private keys for users.
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
CREATE TABLE public_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	identity_id BIGINT,
	rsa_n TEXT,
	rsa_e TEXT,

	PRIMARY KEY( id )
);

CREATE TABLE relid_request
(
	for_user VARCHAR(20),
	from_id TEXT,
	requested_relid VARCHAR(48) BINARY,
	reqid VARCHAR(48) BINARY,
	msg_sym TEXT
);

CREATE TABLE relid_response
(
	from_id TEXT,
	requested_relid VARCHAR(48) BINARY,
	returned_relid VARCHAR(48) BINARY,
	reqid VARCHAR(48) BINARY,
	msg_sym TEXT
);

CREATE TABLE friend_request
(
	for_user VARCHAR(20), 
	from_id TEXT,
	reqid VARCHAR(48) BINARY,
	requested_relid VARCHAR(48) BINARY,
	returned_relid VARCHAR(48) BINARY
);

CREATE TABLE sent_friend_request
(
	from_user VARCHAR(20),
	for_id TEXT,
	requested_relid VARCHAR(48) BINARY,
	returned_relid VARCHAR(48) BINARY
);

CREATE TABLE friend_claim
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	user VARCHAR(20), 
	iduri TEXT,
	friend_salt VARCHAR(48) BINARY,
	friend_hash VARCHAR(48) BINARY,
	put_relid VARCHAR(48) BINARY,
	get_relid VARCHAR(48) BINARY,


	name TEXT,

	type INTEGER,

	PRIMARY KEY( id )
);

CREATE TABLE ftoken_request
(
	user VARCHAR(20), 
	from_id TEXT,
	token VARCHAR(48) BINARY,
	reqid VARCHAR(48) BINARY,
	msg_sym TEXT,
	network_id BIGINT
);

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

CREATE TABLE network_member
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	network_id BIGINT,
	friend_claim_id BIGINT,

	PRIMARY KEY ( id ),
	UNIQUE KEY ( network_id, friend_claim_id )
);


CREATE TABLE broadcast_message
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	key_gen BIGINT,
	tree_gen_low BIGINT,
	tree_gen_high BIGINT,
	message TEXT,
	network_name TEXT,
	
	PRIMARY KEY ( id )
);

CREATE TABLE broadcast_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	message_id BIGINT,
	send_after DATETIME,
	to_site TEXT,
	forward BOOLEAN,

	PRIMARY KEY ( id )
);

CREATE TABLE broadcast_recipient
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	queue_id BIGINT,
	relid VARCHAR(48) BINARY,

	PRIMARY KEY ( id )
);

CREATE TABLE message_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,
	send_after DATETIME,

	from_user VARCHAR(20),
	to_id TEXT,
	relid VARCHAR(48) BINARY,
	message TEXT,

	PRIMARY KEY ( id )
);

CREATE TABLE broadcasted
(
	user VARCHAR(20),
	author_id TEXT,
	subject_id TEXT,
	seq_num BIGINT NOT NULL AUTO_INCREMENT,
	time_published TIMESTAMP,
	type CHAR(4),
	message BLOB,

	PRIMARY KEY ( user, seq_num )
);

CREATE TABLE login_token
(
	user VARCHAR(20),
	login_token VARCHAR(48) BINARY,
	expires TIMESTAMP
);

CREATE TABLE flogin_token
(
	user VARCHAR(20),
	identity TEXT,
	login_token VARCHAR(48) BINARY,
	expires TIMESTAMP
);

CREATE TABLE remote_flogin_token
(
	user VARCHAR(20),
	identity TEXT,
	login_token VARCHAR(48) BINARY
);

CREATE TABLE pending_remote_broadcast
(
	user VARCHAR(20),
	identity TEXT,
	hash TEXT,
	reqid VARCHAR(48) BINARY,
	reqid_final VARCHAR(48) BINARY,
	seq_num BIGINT,
	generation BIGINT,
	sym TEXT,
	network_name TEXT
);

CREATE TABLE remote_broadcast_request
(
	user VARCHAR(20),
	identity TEXT,
	reqid VARCHAR(48) BINARY,
	generation BIGINT,
	sym TEXT
);

--
-- Should have three tables:
--   published_owner: owner's view of what's published
--   published_friend: friend's view of what's published
--   activity_stream: what's going on with the user's friends.
--

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


CREATE TABLE image
(
	user VARCHAR(20),
	seq_num BIGINT NOT NULL AUTO_INCREMENT,
	rows INT,
	cols INT,
	mime_type VARCHAR(32),

	PRIMARY KEY ( user, seq_num )
);

CREATE TABLE put_broadcast_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	network_id BIGINT,

	generation BIGINT,
	broadcast_key VARCHAR(48) BINARY,

	PRIMARY KEY ( id )
);

CREATE TABLE get_broadcast_key
(
	id bigint NOT NULL AUTO_INCREMENT,

	friend_claim_id BIGINT,
	network_id BIGINT,
	generation BIGINT,

	broadcast_key VARCHAR(48) BINARY,
	friend_proof TEXT,
	reverse_proof TEXT,

	PRIMARY KEY ( id ),
	UNIQUE KEY ( network_id, friend_claim_id, generation )
);

-- Database schema verison. Initialize it.
CREATE TABLE version
(
	version INT
);

INSERT INTO version ( version ) VALUES ( 0 );


