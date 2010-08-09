
CREATE TABLE user
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	user VARCHAR(20), 
	pass_salt CHAR(24) BINARY,
	pass VARCHAR(40) BINARY, 

	id_salt CHAR(24) BINARY,

	rsa_n TEXT BINARY,
	rsa_e TEXT BINARY,
	rsa_d TEXT BINARY,
	rsa_p TEXT BINARY,
	rsa_q TEXT BINARY,
	rsa_dmp1 TEXT BINARY,
	rsa_dmq1 TEXT BINARY,
	rsa_iqmp TEXT BINARY,

	identity TEXT,
	name VARCHAR(50),
	email VARCHAR(50),
	type INT,

	UNIQUE(user),
	PRIMARY KEY(id)
);


CREATE TABLE public_key
(
	identity TEXT,
	rsa_n TEXT,
	rsa_e TEXT
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

	user VARCHAR(20), 
	friend_id TEXT,
	friend_salt VARCHAR(48) BINARY,
	friend_hash VARCHAR(48) BINARY,
	put_relid VARCHAR(48) BINARY,
	get_relid VARCHAR(48) BINARY,

	user_id BIGINT,
	identity TEXT,
	name TEXT,
	state INT,

	PRIMARY KEY(id)
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


CREATE TABLE broadcast_message
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	key_gen BIGINT,
	tree_gen_low BIGINT,
	tree_gen_high BIGINT,
	message TEXT,
	network_name TEXT,
	
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
	relid VARCHAR(48) BINARY,

	PRIMARY KEY(id)
);

CREATE TABLE message_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,
	send_after DATETIME,

	from_user VARCHAR(20),
	to_id TEXT,
	relid VARCHAR(48) BINARY,
	message TEXT,

	PRIMARY KEY(id)
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
	PRIMARY KEY(user, seq_num)
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
--   opublished: owner's view of what's published
--   fpublished: friend's view of what's published
--   activity: what's going on with the user's friends.
--

CREATE TABLE published
(
	user VARCHAR(20),
	author_id BIGINT,
	subject_id BIGINT,
	seq_num BIGINT NOT NULL AUTO_INCREMENT,
	time_published TIMESTAMP,
	type CHAR(4),
	resource_id BIGINT,
	message BLOB,
	PRIMARY KEY(user, seq_num)
);

CREATE TABLE remote_published
(
	user VARCHAR(20),
	author_id BIGINT,
	subject_id BIGINT,
	time_published TIMESTAMP,
	type CHAR(4),
	resource_id BIGINT,
	message BLOB
);

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

	PRIMARY KEY(id)
);

CREATE TABLE received
( 
	for_user VARCHAR(20),
	author_id BIGINT,
	subject_id BIGINT,
	seq_num BIGINT,
	time_published TIMESTAMP,
	time_received TIMESTAMP,
	type CHAR(4),
	resource_id BIGINT,
	message BLOB
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

	PRIMARY KEY(user, seq_num)
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

	UNIQUE KEY ( network_id, friend_claim_id, generation ),
	PRIMARY KEY (id)
);

--
-- Groups of friends.
-- 

CREATE TABLE network
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,

	name VARCHAR(20),
	dist_name VARCHAR(48) BINARY,

	key_gen BIGINT,
	tree_gen_low BIGINT,
	tree_gen_high BIGINT,

	PRIMARY KEY ( id ),

	UNIQUE ( user_id, name )
);

CREATE TABLE network_member
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	network_id BIGINT,
	friend_claim_id BIGINT,

	PRIMARY KEY ( id ),

	UNIQUE ( network_id, friend_claim_id )
);

--
-- We received proof that from_fc_id considers to_fc_id a friend.
--

CREATE TABLE friend_link
(
	network_id BIGINT,
	from_fc_id BIGINT,
	to_fc_id BIGINT,

	PRIMARY KEY ( network_id, from_fc_id, to_fc_id )
);


