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


#
# Read the installation location.
#

echo
echo "Please give the Uniform Resource Identifier (URI) of this installation. This"
echo "will be the installations public name. It should start with 'http://' and end"
echo "with '/'."
echo

while true; do 
	read -p 'installation uri: ' URI_IN

	if echo $URI_IN | grep '^http:\/\/.*\/$' >/dev/null; then
		break
	fi
	echo; echo error: uri did not validate; echo
done 

CFG_URI=`echo $URI_IN | sed 's/\/$//;'`
CFG_HOST=`echo $URI_IN | sed 's/^http:\/\///; s/\/.*$//;'`
CFG_PATH=`echo $URI_IN | sed 's/^http:\/\///; s/^[^\/]*//; s/\/$//;'`

echo
echo "Please choose an admin password. This password to protect the database user"
echo "'spp' and the admin login page."
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

echo
echo "Thank you, now initializing the installation."
echo

#
# Init the database.
#

echo Initializing the database. Please login as root@localhost.

mysql -f -h localhost -u root -p << EOF
DROP USER spp@localhost;
DROP DATABASE spp;
CREATE DATABASE spp;
GRANT ALL ON spp.* TO 'spp'@'localhost' IDENTIFIED BY '$CFG_ADMIN_PASS';
USE spp;
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

CREATE TABLE friend_req (
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

CREATE TABLE user_friend_req (
	user VARCHAR(20), 
	from_id TEXT,
	user_reqid CHAR(32),
	fr_relid CHAR(32),
	relid CHAR(32)
);

CREATE TABLE friend_claim (
	user VARCHAR(20), 
	friend_id TEXT,
	put_relid CHAR(32),
	get_relid CHAR(32)
);
EOF

# Make a key for communication from the frontend to backend.
CFG_COMM_KEY=`head -c 24 < /dev/urandom | xxd -p`

CFG_PORT=7070

#
# Create the php config file.
#

cat > php/config.php << EOF
<?php
\$CFG_URI = '$CFG_URI';
\$CFG_HOST = '$CFG_HOST';
\$CFG_PATH = '$CFG_PATH';
\$CFG_DB_HOST = 'localhost';
\$CFG_DB_DATABASE = 'spp';
\$CFG_DB_USER = 'spp';
\$CFG_ADMIN_PASS = '$CFG_ADMIN_PASS';
\$CFG_COMM_KEY = '$CFG_COMM_KEY';
\$CFG_PORT = '$CFG_PORT';
?>
EOF

#
# Create the sppd config file.
#

cat > sppd/sppd.conf << EOF
CFG_URI = $CFG_URI
CFG_HOST = $CFG_HOST
CFG_PATH = $CFG_PATH
CFG_DB_HOST = localhost
CFG_DB_DATABASE = spp
CFG_DB_USER = spp
CFG_ADMIN_PASS = $CFG_ADMIN_PASS
CFG_COMM_KEY = $CFG_COMM_KEY
CFG_PORT = $CFG_PORT
EOF

#
# Init the the .htaccess file.
#

# FIXME: strip the host from the the first rewrite target.
cat > php/.htaccess << EOF
RewriteEngine on

# Add trailing slashes to everything.
RewriteRule ^([a-zA-Z0-9.]+)$          $CFG_PATH/\$1/          [R,L]

# Admin
RewriteRule ^admin/(.*)$               admin/\$1               [L]

# Users
RewriteRule ^([a-zA-Z0-9.]+)/([^\/]*)$  user/\$2?u=\$1          [L,QSA]
EOF

