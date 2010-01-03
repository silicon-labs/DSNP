ALTER TABLE activity ADD COLUMN network_id BIGINT;

UPDATE activity, network_name, network SET activity.network_id = network.id 
	WHERE network_name.name = 'social' AND network_name.id = network.network_name_id 
	AND network.user_id = activity.user_id;

CREATE TABLE login_state
(
	user_id BIGINT,
	network_name TEXT,

	PRIMARY KEY( user_id )
);

INSERT INTO login_state ( user_id, network_name )
	SELECT id, 'social' FROM user;

ALTER TABLE ftoken_request ADD COLUMN network_id BIGINT;
ALTER TABLE flogin_token ADD COLUMN network_id BIGINT;
