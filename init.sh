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
drop user spp@localhost;
drop database spp;
create database spp;
grant all on spp.* to 'spp'@'localhost' identified by '$CFG_ADMIN_PASS';
use spp;
create table user ( 
	user varchar(20), 
	pass varchar(40), 
	email varchar(50),

	rsa_n text, # 256
	rsa_e char(6),
	rsa_d text, # 256
	rsa_p char(128),
	rsa_q char(128),
	rsa_dmp1 char(128),
	rsa_dmq1 char(128),
	rsa_iqmp char(128)
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

RewriteRule ^u/([a-zA-Z0-9.]+)$ 	$CFG_PATH/u/\$1/ [R,L]

# Users
RewriteRule ^u/([a-zA-Z0-9.]+)$ 	user/index.php?u=\$1
RewriteRule ^u/([a-zA-Z0-9.]+)/(.*)$ 	user/\$2?u=\$1          [QSA,L]
EOF

