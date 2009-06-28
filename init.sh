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

PHP_CONF=php/config.php
SPPD_CONF=sppd/sppd.conf

#
# Config for all sites
#

# Make a key for communication from the frontend to backend.
CFG_COMM_KEY=`head -c 24 < /dev/urandom | xxd -p`

# Port for the server.
CFG_PORT=7070

# start the config files
{ echo '<?php'; echo; } > $PHP_CONF
echo > $SPPD_CONF

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
DROP USER '${NAME}_owner'@'localhost';
CREATE USER '${NAME}_owner'@'localhost' IDENTIFIED BY '$CFG_ADMIN_PASS';

DROP DATABASE $NAME;
CREATE DATABASE $NAME;
GRANT ALL ON $NAME.* TO '${NAME}_owner'@'localhost';
USE $NAME;
CREATE TABLE user ( 
	user VARCHAR(20), 
	salt CHAR(24),
	pass VARCHAR(40), 
	email VARCHAR(50),

	rsa_n TEXT,
	rsa_e TEXT,
	rsa_d TEXT,
	rsa_p TEXT,
	rsa_q TEXT,
	rsa_dmp1 TEXT,
	rsa_dmq1 TEXT,
	rsa_iqmp TEXT
);

CREATE TABLE public_key (
	identity TEXT,
	rsa_n TEXT,
	rsa_e TEXT
);

CREATE TABLE relid_request (
	for_user VARCHAR(20),
	from_id TEXT,
	requested_relid VARCHAR(48),
	reqid VARCHAR(48),
	msg_sym TEXT
);

CREATE TABLE relid_response (
	from_id TEXT,
	requested_relid VARCHAR(48),
	returned_relid VARCHAR(48),
	reqid VARCHAR(48),
	msg_sym TEXT
);

CREATE TABLE friend_request (
	for_user VARCHAR(20), 
	from_id TEXT,
	reqid VARCHAR(48),
	requested_relid VARCHAR(48),
	returned_relid VARCHAR(48)
);

CREATE TABLE get_broadcast_key (
	get_relid VARCHAR(48),
	generation BIGINT,
	broadcast_key VARCHAR(48)
);

CREATE TABLE put_broadcast_key (
	user VARCHAR(20), 
	generation BIGINT,
	broadcast_key VARCHAR(48)
);

CREATE TABLE friend_claim (
	user VARCHAR(20), 
	friend_id TEXT,
	friend_hash VARCHAR(48),
	put_relid VARCHAR(48),
	get_relid VARCHAR(48),
	acknowledged BOOL,
	put_root BOOL,
	put_forward1 TEXT,
	put_forward2 TEXT,
	get_fwd_site1 TEXT,
	get_fwd_site2 TEXT,
	get_fwd_relid1 VARCHAR(48),
	get_fwd_relid2 VARCHAR(48)
);

CREATE TABLE ftoken_request (
	user VARCHAR(20), 
	from_id TEXT,
	token VARCHAR(48),
	reqid VARCHAR(48),
	msg_sym TEXT
);

CREATE TABLE broadcast_queue (
	to_site TEXT,
	relid VARCHAR(48),
	generation BIGINT,
	message TEXT
);

CREATE TABLE message_queue (
	to_id TEXT,
	relid VARCHAR(48),
	message TEXT
);

CREATE TABLE received ( 
	for_user VARCHAR(20),
	author_id TEXT,
	subject_id TEXT,
	seq_num BIGINT,
	time_published TIMESTAMP,
	time_received TIMESTAMP,
	message BLOB
);

CREATE TABLE published (
	user VARCHAR(20),
	author_id TEXT,
	subject_id TEXT,
	seq_num BIGINT NOT NULL AUTO_INCREMENT,
	time_published TIMESTAMP,
	message BLOB,
	PRIMARY KEY(user, seq_num)
);

CREATE TABLE remote_published (
	user VARCHAR(20),
	author_id TEXT,
	subject_id TEXT,
	time_published TIMESTAMP,
	message BLOB
);

CREATE TABLE login_token (
	user VARCHAR(20),
	login_token VARCHAR(48),
	expires TIMESTAMP
);

CREATE TABLE flogin_token (
	user VARCHAR(20),
	identity TEXT,
	login_token VARCHAR(48),
	expires TIMESTAMP
);

CREATE TABLE remote_flogin_token (
	user VARCHAR(20),
	identity TEXT,
	login_token VARCHAR(48)
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
	\$CFG_DB_USER = '${NAME}_owner';
	\$CFG_DB_DATABASE = '$NAME';
	\$CFG_ADMIN_PASS = '$CFG_ADMIN_PASS';
	\$CFG_COMM_KEY = '$CFG_COMM_KEY';
	\$CFG_PORT = '$CFG_PORT';
	\$CFG_USE_RECAPTCHA = false;
	\$CFG_RC_PUBLIC_KEY = 'xxxx';
}

EOF

#
# Add the site to the sppd config file.
#

cat >> $SPPD_CONF << EOF
===== $NAME =====
CFG_URI = $CFG_URI
CFG_HOST = $CFG_HOST
CFG_PATH = $CFG_PATH
CFG_DB_HOST = localhost
CFG_DB_USER = ${NAME}_owner
CFG_DB_DATABASE = $NAME
CFG_ADMIN_PASS = $CFG_ADMIN_PASS
CFG_COMM_KEY = $CFG_COMM_KEY
CFG_PORT = $CFG_PORT
CFG_TLS_CA_CERTS = /etc/ssl/certs/ca-certificates.crt
CFG_TLS_CRT = /etc/ssl/local/localhost.crt
CFG_TLS_KEY = /etc/ssl/local/localhost.key

EOF

done

echo
echo "Thank you, now initializing the database. Please login as root@localhost."
echo "Please ignore any \"Can't drop\" messages."
echo

mysql -f -h localhost -u root -p < init.sql
rm init.sql

# Finish the PHP config file.
cat >> $PHP_CONF << EOF
if ( !\$CFG_URI ) {
	die('config.php: could not select installation');
}

if ( get_magic_quotes_gpc() ) {
	die('the SPP software assumes PHP magic quotes to be off');
}

\$USER_NAME = isset( \$_GET['u'] ) ? \$_GET['u'] : "";
\$USER_PATH = "\${CFG_PATH}\$USER_NAME/";
\$USER_URI = "\${CFG_URI}\$USER_NAME/";

include('error.php');

?>
EOF

