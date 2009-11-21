
ALTER TABLE put_tree ADD COLUMN active BOOL;
UPDATE put_tree SET active = true;
