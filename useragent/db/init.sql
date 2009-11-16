CREATE TABLE user
( 
	id BIGINT NOT NULL AUTO_INCREMENT,
	user VARCHAR(20), 
	identity TEXT,
	name VARCHAR(50),
	email VARCHAR(50),

	PRIMARY KEY(id)
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
	for_id TEXT
);

CREATE TABLE friend_claim
(
	id BIGINT NOT NULL AUTO_INCREMENT,
	user_id BIGINT,
	identity TEXT,
	name TEXT,

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
	time_published TIMESTAMP,
	time_received TIMESTAMP,
	type CHAR(4),
	resource_id BIGINT,
	message BLOB,

	PRIMARY KEY(id)
);

CREATE TABLE image
(
	user VARCHAR(20),
	seq_num BIGINT NOT NULL AUTO_INCREMENT,
	rows INT,
	cols INT,
	mime_type VARCHAR(32),

	PRIMARY KEY(user, seq_num)
);

