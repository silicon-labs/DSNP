#!/bin/bash
#
# Copyright (c) 2007, 2008, Adrian Thurston <thurston@complang.org>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

PHP_CONF=php/app/config/config.php

#
# Config for all sites
#

# Make a key for communication from the frontend to backend.
CFG_COMM_KEY=`head -c 24 < /dev/urandom | xxd -p`

# Port for the server.
CFG_PORT=7085

# Start the config file.
{ echo '<?php'; echo; } >> $PHP_CONF

cat << EOF
Please choose a password to protect the new database users with. Every site you
create during this run will have a new user with this password. The user name
will be derived from the site name.

EOF

while true; do
	read -s -p 'password: ' CFG_ADMIN_PASS; echo
	read -s -p '   again: ' AGAIN; echo

	if [ "$CFG_ADMIN_PASS" != "$AGAIN" ]; then
		echo; echo error: passwords do not match; echo
		continue
	fi

	if [ -z "$CFG_ADMIN_PASS" ]; then
		echo; echo error: password must not be empty; echo 
		continue
	fi
	break;
done

#
# Start reading installations.
#

echo
echo "Thank you. You can now add sites."

# Clear the database init file
rm -f init.sql 
while true; do

echo
echo "Please give a short name for the site. It should contain only letters and"
echo "numbers and should begin with a letter. This name will be used internally to"
echo "identify the installation. It will not be visible to the user. If you are"
echo "finished giving installations just press enter."
echo

while true; do 
	read -p 'installation name: ' NAME

	if [ -z "$NAME" ]; then
		done=yes;
		break;
	fi
	if echo $NAME | grep '^[a-zA-Z][a-zA-Z0-9]*$' >/dev/null; then
		break
	fi
	echo; echo error: name did not validate; echo
done 

[ -n "$done" ] && break;

echo
echo "Please give the Uniform Resource Identifier (URI) of this site. This will be"
echo "the installations public name. It should start with 'https://' and end with '/'."
echo

while true; do 
	read -p 'installation uri: ' URI_IN

	if echo $URI_IN | grep '^https:\/\/.*\/$' >/dev/null; then
		break
	fi
	echo; echo error: uri did not validate; echo
done 

CFG_HOST=`echo $URI_IN | sed 's/^https:\/\///; s/\/.*$//;'`
CFG_URI=$URI_IN;
CFG_PATH=`echo $URI_IN | sed 's/^https:\/\///; s/^[^\/]*//;'`

#
# Init the database.
#


cat >> init.sql << EOF
DROP USER 'dua_${NAME}'@'localhost';
CREATE USER 'dua_${NAME}'@'localhost' IDENTIFIED BY '$CFG_ADMIN_PASS';

DROP DATABASE dua_${NAME};
CREATE DATABASE dua_${NAME};
GRANT ALL ON dua_${NAME}.* TO 'dua_${NAME}'@'localhost';
USE dua_${NAME};

CREATE TABLE user
( 
	id BIGINT NOT NULL AUTO_INCREMENT,
	user VARCHAR(20), 
	name VARCHAR(50),
	email VARCHAR(50),

	PRIMARY KEY(id)
);

CREATE TABLE friend_request
(
	for_user VARCHAR(20), 
	from_id TEXT,
	reqid VARCHAR(48),
	requested_relid VARCHAR(48),
	returned_relid VARCHAR(48)
);

CREATE TABLE sent_friend_request
(
	from_user VARCHAR(20),
	for_id TEXT
);

CREATE TABLE friend_claim
(
	id BIGINT NOT NULL AUTO_INCREMENT,
	user_id BIGINT,
	friend_id TEXT,
	name TEXT,

	PRIMARY KEY(id)
);

CREATE TABLE received
( 
	for_user VARCHAR(20),
	author_id BIGINT,
	subject_id BIGINT,
	seq_num BIGINT,
	time_published TIMESTAMP,
	time_received TIMESTAMP,
	type CHAR(4),
	resource_id BIGINT,
	message BLOB
);

CREATE TABLE published
(
	user VARCHAR(20),
	author_id BIGINT,
	subject_id BIGINT,
	seq_num BIGINT NOT NULL AUTO_INCREMENT,
	time_published TIMESTAMP,
	type CHAR(4),
	resource_id BIGINT,
	message BLOB,
	PRIMARY KEY(user, seq_num)
);

CREATE TABLE remote_published
(
	user VARCHAR(20),
	author_id BIGINT,
	subject_id BIGINT,
	time_published TIMESTAMP,
	type CHAR(4),
	resource_id BIGINT,
	message BLOB
);

CREATE TABLE activity
( 
	id BIGINT NOT NULL AUTO_INCREMENT,

	user VARCHAR(20),
	author_id BIGINT,
	subject_id BIGINT,
	published BOOL,
	seq_num BIGINT,
	time_published TIMESTAMP,
	time_received TIMESTAMP,
	type CHAR(4),
	resource_id BIGINT,
	message BLOB,

	PRIMARY KEY(id)
);

CREATE TABLE image
(
	user VARCHAR(20),
	seq_num BIGINT NOT NULL AUTO_INCREMENT,
	rows INT,
	cols INT,
	mime_type VARCHAR(32),

	PRIMARY KEY(user, seq_num)
);

EOF

#
# Add the site to the PHP config file.
#

cat >> $PHP_CONF << EOF
if ( strpos( \$_SERVER['HTTP_HOST'] . \$_SERVER['REQUEST_URI'], '$CFG_HOST$CFG_PATH' ) === 0 ) {
	\$CFG_URI = '$CFG_URI';
	\$CFG_HOST = '$CFG_HOST';
	\$CFG_PATH = '$CFG_PATH';
	\$CFG_DB_HOST = 'localhost';
	\$CFG_DB_USER = 'dua_${NAME}';
	\$CFG_DB_DATABASE = 'dua_${NAME}';
	\$CFG_ADMIN_PASS = '$CFG_ADMIN_PASS';
	\$CFG_COMM_KEY = '$CFG_COMM_KEY';
	\$CFG_PORT = $CFG_PORT;
	\$CFG_USE_RECAPTCHA = SET_THIS;
	\$CFG_RC_PUBLIC_KEY = SET_THIS;
	\$CFG_RC_PRIVATE_KEY = SET_THIS;
	\$CFG_PHOTO_DIR = SET_THIS;
	\$CFG_IM_CONVERT = SET_THIS;
}

EOF

(
	set -x
	mkdir -p data/$NAME
	rm -Rf data/$NAME/*
)

done

echo
echo "Thank you, now initializing the database. Please login as root@localhost."
echo "Please ignore any \"Can't drop\" messages."
echo

mysql -f -h localhost -u root -p < init.sql
rm init.sql

# Finish the PHP config file.
cat >> $PHP_CONF << EOF
?>
EOF

