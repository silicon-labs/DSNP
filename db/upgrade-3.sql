DROP TABLE broadcast_queue;
DROP TABLE message_queue;

CREATE TABLE broadcast_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,
	send_after DATETIME,

	to_site TEXT,
	relid VARCHAR(48),
	generation BIGINT,
	message TEXT,
	

	PRIMARY KEY(id)
);

CREATE TABLE message_queue
(
	id BIGINT NOT NULL AUTO_INCREMENT,
	send_after DATETIME,

	from_user VARCHAR(20),
	to_id TEXT,
	relid VARCHAR(48),
	message TEXT,

	PRIMARY KEY(id)
);
