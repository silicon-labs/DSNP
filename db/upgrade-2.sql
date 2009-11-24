ALTER TABLE pending_remote_broadcast DROP COLUMN message;
ALTER TABLE friend_claim ADD COLUMN fp_generation BIGINT;
ALTER TABLE friend_claim ADD COLUMN friend_proof TEXT;
