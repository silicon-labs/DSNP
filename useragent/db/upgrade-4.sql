ALTER TABLE activity CHANGE COLUMN resource_id remote_resid BIGINT;
ALTER TABLE activity ADD COLUMN local_resid BIGINT;

UPDATE activity set local_resid = CAST( REPLACE( SUBSTR( message, 5 ), '.jpg', '' ) as SIGNED ) 
	WHERE published IS NOT NULL AND type = 'PHT';

UPDATE activity set local_resid = CAST( REPLACE( SUBSTR( message, 5 ), '.jpg', '' ) as SIGNED )
	WHERE published IS NULL AND author_id IS NOT NULL AND subject_id IS NULL AND type = 'PHT';
