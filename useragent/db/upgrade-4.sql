ALTER TABLE activity CHANGE COLUMN resource_id remote_resid BIGINT;
ALTER TABLE activity ADD COLUMN local_resid BIGINT;

ALTER TABLE activity CHANGE COLUMN time_published time_published TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE activity CHANGE COLUMN time_received time_received TIMESTAMP DEFAULT 0;

UPDATE activity set local_resid = CAST( REPLACE( SUBSTR( message, 5 ), '.jpg', '' ) as SIGNED ) 
	WHERE published IS NOT NULL AND type = 'PHT';

UPDATE activity set local_resid = CAST( REPLACE( SUBSTR( message, 5 ), '.jpg', '' ) as SIGNED )
	WHERE published IS NULL AND author_id IS NOT NULL AND subject_id IS NULL AND type = 'PHT';
