ALTER TABLE friend_claim ADD COLUMN state INT;
UPDATE friend_claim SET state = 0;
