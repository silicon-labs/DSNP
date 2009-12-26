ALTER TABLE friend_claim_ua ADD COLUMN state INT;
UPDATE friend_claim_ua SET state = 0;
