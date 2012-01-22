-- Passwords
DROP TABLE IF EXISTS password;
CREATE TABLE password
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,
	pass_salt CHAR(24) BINARY,
	pass VARCHAR(40) BINARY, 

	PRIMARY KEY( id )
);

-- Fetched public keys.
DROP TABLE IF EXISTS public_key;
CREATE TABLE public_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	identity_id BIGINT,
	key_priv INT,

	key_data   BLOB,

	PRIMARY KEY( id )
);

-- Set of signed public keys for a user.
DROP TABLE IF EXISTS public_key_set;
CREATE TABLE public_key_set
(
	id BIGINT NOT NULL AUTO_INCREMENT,
	
	user_id    BIGINT,
	key_data   BLOB,

	PRIMARY KEY( id )
);

-- Public and Private keys for users.
DROP TABLE IF EXISTS private_key;
CREATE TABLE private_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,
	
	user_id    BIGINT,
	key_priv   INT,
	encrypted  BOOLEAN,
	key_data   BLOB,

	PRIMARY KEY( id )
);

DROP TABLE IF EXISTS put_broadcast_key;
CREATE TABLE put_broadcast_key
(
	id BIGINT,
	broadcast_key VARCHAR(48) BINARY,

	-- The private key for the put broadcast key.
	priv_key   BLOB,
	pub_key   BLOB,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS friend_claim;
CREATE TABLE friend_claim
(
	id BIGINT,

	-- The private key for the put broadcast key.
	direct_key_data BLOB,
	rb_key_data BLOB,

	recv_pub_key BLOB,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS get_broadcast_key;
CREATE TABLE get_broadcast_key
(
	id BIGINT,
	broadcast_key VARCHAR(48) BINARY,
	pub_key BLOB,
	member_proof BLOB,

	PRIMARY KEY ( id )
);

DROP TABLE IF EXISTS rb_key;
CREATE TABLE rb_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	get_broadcast_key_id BIGINT,
	identity_id BIGINT,

	hash VARCHAR(48) BINARY,
	key_data BLOB,

	PRIMARY KEY ( id )
);
