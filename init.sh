#!/bin/bash
#
# Copyright (c) 2007, 2008, Adrian Thurston <thurston@cs.queensu.ca>
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

echo
echo "Please choose an admin password. This password will protect the database user"
echo "'spp' and the admin login page of all sites."
echo

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

rm -f init.sql
cat > init.sql << EOF
DROP USER 'spp'@'localhost';
CREATE USER 'spp'@'localhost' IDENTIFIED BY '$CFG_ADMIN_PASS';
EOF

#
# Start reading installations.
#

echo
echo "Thank you. You can now add sites."

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
echo "the installations public name. It should start with 'http://' and end with '/'."
echo

while true; do 
	read -p 'installation uri: ' URI_IN

	if echo $URI_IN | grep '^http:\/\/.*\/$' >/dev/null; then
		break
	fi
	echo; echo error: uri did not validate; echo
done 

CFG_HOST=`echo $URI_IN | sed 's/^http:\/\///; s/\/.*$//;'`
CFG_URI=$URI_IN;
CFG_PATH=`echo $URI_IN | sed 's/^http:\/\///; s/^[^\/]*//;'`

#
# Init the database.
#

cat >> init.sql << EOF
DROP DATABASE $NAME;
CREATE DATABASE $NAME;
GRANT ALL ON $NAME.* TO 'spp'@'localhost';
USE $NAME;
CREATE TABLE user ( 
	user VARCHAR(20), 
	pass VARCHAR(40), 
	email VARCHAR(50),

	rsa_n TEXT, # 256
	rsa_e CHAR(6),
	rsa_d TEXT, # 256
	rsa_p CHAR(128),
	rsa_q CHAR(128),
	rsa_dmp1 CHAR(128),
	rsa_dmq1 CHAR(128),
	rsa_iqmp CHAR(128)
);

CREATE TABLE public_key (
	identity TEXT,
	rsa_n TEXT,
	rsa_e CHAR(6)
);

CREATE TABLE friend_request (
	from_id TEXT,
	fr_relid CHAR(32),
	fr_reqid CHAR(32),
	msg_enc TEXT,
	msg_sig TEXT
);

CREATE TABLE return_relid (
	from_id TEXT,
	fr_relid CHAR(32),
	fr_reqid CHAR(32),
	relid CHAR(32),
	reqid CHAR(32),
	msg_enc TEXT,
	msg_sig TEXT
);

CREATE TABLE user_friend_request (
	user VARCHAR(20), 
	from_id TEXT,
	user_reqid CHAR(32),
	fr_relid CHAR(32),
	relid CHAR(32)
);

CREATE TABLE get_session_key (
	user VARCHAR(20), 
	friend_id TEXT,
	session_key CHAR(32),
	generation BIGINT
);

CREATE TABLE put_session_key (
	user VARCHAR(20), 
	session_key CHAR(32),
	generation BIGINT
);

CREATE TABLE friend_claim (
	user VARCHAR(20), 
	friend_id TEXT,
	friend_hash CHAR(32),
	put_relid CHAR(32),
	get_relid CHAR(32),
	acknowledged BOOL,
	put_root BOOL,
	put_forward1 TEXT,
	put_forward2 TEXT,
	get_forward1 TEXT,
	get_forward2 TEXT
);

CREATE TABLE flogin_tok (
	user VARCHAR(20), 
	from_id TEXT,
	flogin_tok CHAR(32),
	flogin_reqid CHAR(32),
	msg_enc TEXT,
	msg_sig TEXT
);

CREATE TABLE msg_queue (
	from_user VARCHAR(20),
	to_id TEXT,
	message TEXT
);

EOF

#
# Add the site to the PHP config file.
#

cat >> $PHP_CONF << EOF
if ( strpos( \$_SERVER['REQUEST_URI'], '$CFG_PATH' ) === 0 ) {
	\$CFG_URI = '$CFG_URI';
	\$CFG_HOST = '$CFG_HOST';
	\$CFG_PATH = '$CFG_PATH';
	\$CFG_DB_HOST = 'localhost';
	\$CFG_DB_DATABASE = '$NAME';
	\$CFG_DB_USER = 'spp';
	\$CFG_ADMIN_PASS = '$CFG_ADMIN_PASS';
	\$CFG_COMM_KEY = '$CFG_COMM_KEY';
	\$CFG_PORT = '$CFG_PORT';
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
CFG_DB_DATABASE = $NAME
CFG_DB_USER = spp
CFG_ADMIN_PASS = $CFG_ADMIN_PASS
CFG_COMM_KEY = $CFG_COMM_KEY
CFG_PORT = $CFG_PORT

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

?>
EOF

