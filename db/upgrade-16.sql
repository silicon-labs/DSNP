ALTER TABLE get_broadcast_key ADD COLUMN reverse_proof TEXT;
ALTER TABLE friend_link ADD COLUMN group_name TEXT;
UPDATE friend_link SET group_name = 'social';
