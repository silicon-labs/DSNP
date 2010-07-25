ALTER TABLE flogin_token DROP COLUMN network_id;

DROP TABLE network;
CREATE TABLE network
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	user_id BIGINT,

	name VARCHAR(48),
	dist_name VARCHAR(48),

	key_gen BIGINT,
	tree_gen_low BIGINT,
	tree_gen_high BIGINT,

	PRIMARY KEY ( id ),

	UNIQUE ( user_id, name )
);

DROP TABLE network_name;
