ALTER TABLE flogin_token DROP COLUMN network_id;

ALTER TABLE network ADD COLUMN private_name VARCHAR(48);
ALTER TABLE network ADD COLUMN dist_name VARCHAR(48);
