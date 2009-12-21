
ALTER TABLE put_broadcast_key ADD COLUMN group_name TEXT;
UPDATE put_broadcast_key set group_name = 'friend';

ALTER TABLE get_broadcast_key ADD COLUMN group_name TEXT;
UPDATE get_broadcast_key set group_name = 'friend';

ALTER TABLE put_tree ADD COLUMN group_name TEXT;
UPDATE put_tree set group_name = 'friend';

ALTER TABLE get_tree ADD COLUMN group_name TEXT;
UPDATE get_tree set group_name = 'friend';


ALTER TABLE friend_group ADD COLUMN key_gen BIGINT;
ALTER TABLE friend_group ADD COLUMN tree_gen_low BIGINT;
ALTER TABLE friend_group ADD COLUMN tree_gen_high BIGINT;

UPDATE friend_group JOIN user ON friend_group.user_id = user.id 
SET friend_group.key_gen = user.key_gen,
	friend_group.tree_gen_low = user.tree_gen_low,
	friend_group.tree_gen_high = user.tree_gen_high;

ALTER TABLE user DROP column key_gen;
ALTER TABLE user DROP column tree_gen_low;
ALTER TABLE user DROP column tree_gen_high;

CREATE TEMPORARY TABLE put_broadcast_key_copy LIKE put_broadcast_key;
INSERT INTO put_broadcast_key_copy SELECT * FROM put_broadcast_key;

DROP TABLE put_broadcast_key;
CREATE TABLE put_broadcast_key
(
	id BIGINT NOT NULL AUTO_INCREMENT,

	friend_group_id BIGINT,
	generation BIGINT,
	broadcast_key VARCHAR(48),

	PRIMARY KEY(id)
);

INSERT INTO put_broadcast_key
(
	friend_group_id,
	generation,
	broadcast_key
)
	SELECT friend_group.id as friend_group_id, 
		put_broadcast_key_copy.generation, 
		put_broadcast_key_copy.broadcast_key 
	FROM user JOIN friend_group ON user.id = friend_group.user_id 
	JOIN put_broadcast_key_copy ON user.user = put_broadcast_key_copy.user AND 
		friend_group.name = put_broadcast_key_copy.group_name;

--
-- put_tree
--

CREATE TEMPORARY TABLE put_tree_copy LIKE put_tree;
INSERT INTO put_tree_copy SELECT * from put_tree;
DELETE FROM put_tree;
ALTER TABLE put_tree DROP COLUMN group_name;
ALTER TABLE put_tree ADD COLUMN friend_group_id BIGINT;
INSERT INTO put_tree
(
	friend_claim_id,
	friend_group_id, 
	generation,
	root,
	forward1,
	forward2,
	active,
	state
)
	SELECT friend_claim_id, friend_group.id, generation, root, forward1, forward2, active, state
	FROM put_tree_copy
	JOIN friend_claim ON put_tree_copy.friend_claim_id = friend_claim.id
	JOIN user on friend_claim.user = user.user
	JOIN friend_group on user.id = friend_group.user_id AND friend_group.name = put_tree_copy.group_name;
DROP TABLE put_tree_copy;

CREATE TAbLE get_broadcast_key_copy LIKE get_broadcast_key;
INSERT INTO get_broadcast_key_copy SELECT * FROM get_broadcast_key GROUP BY friend_claim_id, broadcast_key;
DELETE FROM get_broadcast_key;
INSERT INTO get_broadcast_key SELECT * FROM get_broadcast_key_copy;
DROP TABLE get_broadcast_key_copy;

ALTER TABLE user DROP COLUMN email;
