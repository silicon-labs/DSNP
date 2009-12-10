ALTER TABLE user RENAME user_orig;

CREATE TABLE user
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

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
	rsa_iqmp TEXT,

	PRIMARY KEY(id)
);

INSERT INTO user ( 
	user, pass_salt, pass,
	email, id_salt, put_generation,
	rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp
)
SELECT 
	user, pass_salt, pass,
	email, id_salt, put_generation,
	rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp
FROM user_orig;


ALTER TABLE friend_claim RENAME friend_claim_orig;

CREATE TABLE friend_claim
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user VARCHAR(20), 
	friend_id TEXT,
	friend_salt VARCHAR(48),
	friend_hash VARCHAR(48),
	put_relid VARCHAR(48),
	get_relid VARCHAR(48),

	PRIMARY KEY(id)
);

INSERT INTO friend_claim (
	user, friend_id, friend_salt,
	friend_hash, put_relid, get_relid
)
SELECT
	user, friend_id, friend_salt,
	friend_hash, put_relid, get_relid
FROM friend_claim_orig;

CREATE TABLE get_broadcast_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	friend_claim_id BIGINT,
	generation BIGINT,
	broadcast_key VARCHAR(48),
	friend_proof TEXT,

	PRIMARY KEY(id)
);

INSERT INTO get_broadcast_key 
(
	friend_claim_id,
	generation,
	broadcast_key,
	friend_proof
)
SELECT friend_claim.id AS friend_claim_id, get_tree.generation, 
	get_tree.broadcast_key, friend_claim_orig.friend_proof
FROM get_tree
JOIN friend_claim ON get_tree.user = friend_claim.user AND 
	get_tree.friend_id = friend_claim.friend_id
JOIN friend_claim_orig ON get_tree.user = friend_claim_orig.user AND 
	get_tree.friend_id = friend_claim_orig.friend_id;

ALTER TABLE put_tree RENAME put_tree_orig;

--CREATE TABLE put_tree
--(
--	id BIGINT NOT NULL AUTO_INCREMENT,
--
--	friend_claim_id BIGINT,
--
--	generation BIGINT,
--	root BOOL,
--	forward1 TEXT,
--	forward2 TEXT,
--
--	PRIMARY KEY(id)
--);
--
--INSERT INTO put_tree
--(
--	friend_claim_id,
--	generation,
--	root,
--	forward1,
--	forward2
--)
--SELECT friend_claim.id AS friend_claim_id, generation, root, forward1, forward2
--FROM put_tree_orig
--JOIN friend_claim ON put_tree_orig.user = friend_claim.user AND put_tree_orig.friend_id = friend_claim.friend_id;


ALTER TABLE get_tree RENAME get_tree_orig;
	
CREATE TABLE get_tree
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	friend_claim_id BIGINT,

	generation BIGINT,
	site1 TEXT,
	site2 TEXT,
	site_ret TEXT,
	relid1 VARCHAR(48),
	relid2 VARCHAR(48),
	relid_ret VARCHAR(48),

	PRIMARY KEY(id)
);

INSERT INTO get_tree
(
	friend_claim_id,
	generation,
	site1,
	site2,
	site_ret,
	relid1,
	relid2,
	relid_ret
)
SELECT friend_claim.id AS friend_claim_id, generation, 
	site1, site2, site_ret, relid1, relid2, relid_ret
FROM get_tree_orig
JOIN friend_claim ON get_tree_orig.user = friend_claim.user AND 
	get_tree_orig.friend_id = friend_claim.friend_id;

DROP TABLE user_orig;
DROP TABLE friend_claim_orig;
DROP TABLE put_tree_orig;
DROP TABLE get_tree_orig;
