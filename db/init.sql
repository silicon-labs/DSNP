
CREATE TABLE user
( 
	user VARCHAR(20), 
	pass_salt CHAR(24),
	pass VARCHAR(40), 

	email VARCHAR(50),
	id_salt CHAR(24),
	put_generation BIGINT,

	rsa_n TEXT,
	rsa_e TEXT,
	rsa_d TEXT,
	rsa_p TEXT,
	rsa_q TEXT,
	rsa_dmp1 TEXT,
	rsa_dmq1 TEXT,
	rsa_iqmp TEXT
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
	requested_relid VARCHAR(48),
	reqid VARCHAR(48),
	msg_sym TEXT
);

CREATE TABLE relid_response
(
	from_id TEXT,
	requested_relid VARCHAR(48),
	returned_relid VARCHAR(48),
	reqid VARCHAR(48),
	msg_sym TEXT
);

CREATE TABLE friend_request
(
	for_user VARCHAR(20), 
	from_id TEXT,
	reqid VARCHAR(48),
	requested_relid VARCHAR(48),
	returned_relid VARCHAR(48)
);

CREATE TABLE sent_friend_request
(
	from_user VARCHAR(20),
	for_id TEXT,
	requested_relid VARCHAR(48),
	returned_relid VARCHAR(48)
);

CREATE TABLE put_broadcast_key
(
	user VARCHAR(20), 
	generation BIGINT,
	broadcast_key VARCHAR(48)
);

CREATE TABLE friend_claim
(
	user VARCHAR(20), 
	friend_id TEXT,
	friend_salt VARCHAR(48),
	friend_hash VARCHAR(48),
	put_relid VARCHAR(48),
	get_relid VARCHAR(48)
);

CREATE TABLE put_tree
(
	user VARCHAR(20),
	friend_id TEXT,
	generation BIGINT,
	root BOOL,
	forward1 TEXT,
	forward2 TEXT
);

CREATE TABLE get_tree
(
	user VARCHAR(20),
	friend_id TEXT,
	generation BIGINT,
	broadcast_key VARCHAR(48),
	site1 TEXT,
	site2 TEXT,
	site_ret TEXT,
	relid1 VARCHAR(48),
	relid2 VARCHAR(48),
	relid_ret VARCHAR(48)
);

CREATE TABLE ftoken_request
(
	user VARCHAR(20), 
	from_id TEXT,
	token VARCHAR(48),
	reqid VARCHAR(48),
	msg_sym TEXT
);

CREATE TABLE broadcast_queue
(
	to_site TEXT,
	relid VARCHAR(48),
	generation BIGINT,
	message TEXT
);

CREATE TABLE message_queue
(
	from_user VARCHAR(20),
	to_id TEXT,
	relid VARCHAR(48),
	message TEXT
);

CREATE TABLE broadcasted
(
	user VARCHAR(20),
	author_id TEXT,
	subject_id TEXT,
	seq_num BIGINT NOT NULL AUTO_INCREMENT,
	time_published TIMESTAMP,
	type CHAR(4),
	resource_id BIGINT,
	message BLOB,
	PRIMARY KEY(user, seq_num)
);

CREATE TABLE login_token
(
	user VARCHAR(20),
	login_token VARCHAR(48),
	expires TIMESTAMP
);

CREATE TABLE flogin_token
(
	user VARCHAR(20),
	identity TEXT,
	login_token VARCHAR(48),
	expires TIMESTAMP
);

CREATE TABLE remote_flogin_token
(
	user VARCHAR(20),
	identity TEXT,
	login_token VARCHAR(48)
);

CREATE TABLE pending_remote_broadcast
(
	user VARCHAR(20),
	identity TEXT,
	hash TEXT,
	reqid VARCHAR(48),
	reqid_final VARCHAR(48),
	seq_num BIGINT,
	message BLOB,
	generation BIGINT,
	sym TEXT
);

CREATE TABLE remote_broadcast_request
(
	user VARCHAR(20),
	identity TEXT,
	reqid VARCHAR(48),
	generation BIGINT,
	sym TEXT
);
