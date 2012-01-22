#!/bin/bash
#
# Copyright (c) 2007-2011, Adrian Thurston <thurston@complang.org>
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

PHP_CONF=@sysconfdir@/choicesocial.php
DATADIR=@datadir@
LOCALSTATEDIR=@localstatedir@
SYSCONFDIR=@sysconfdir@
PREFIX=@prefix@
WWW_USER=@WWW_USER@
WITH_DSNPD=@WITH_DSNPD@

#
# Config for all sites
#

# Port for the server.
CFG_PORT=7085

function usage()
{
	echo usage: ./new-site.sh instructions-file
	exit 1;
}

# Write config file fragments to this file. It can then be copy-pasted to the
# right places. It will contain instructions.
OUTPUT=$1;
if [ -z "$OUTPUT" ]; then
	usage;
	exit 1;
fi

# Clear the output file.
rm -f $OUTPUT;
touch $OUTPUT;
chmod 600 $OUTPUT;

echo
echo "Please give a short name for the site. It should contain only letters and"
echo "numbers. It should begin with a letter. This name will be used internally to"
echo "identify the installation. It will also be used the MYSQL user and database"
echo "names. It will not be visible to any user of the site. 10 characters or less."
echo

while true; do 
	read -p 'installation name: ' NAME

	if [ -z "$NAME" ]; then
		done=yes;
		break;
	fi
	if echo $NAME | grep '^[a-zA-Z][a-zA-Z0-9]*$' >/dev/null; then
		if test ${#NAME} -le 10; then
			break
		fi
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

CFG_HOST=`echo $URI_IN | sed 's|^https://||; s|/.*$||; s|/$||'`
CFG_URI=$URI_IN;
CFG_PATH=`echo $URI_IN | sed 's|^https://||; s|^[^/]*||; s|/$||'`

# Make a password for the database.
CFG_DB_PASS=`head -c 8 < /dev/urandom | xxd -p`

#
# Add the site to the choicesocial config file.
#

cat << EOF > $OUTPUT
INSTALL INSTRUCTIONS: $NAME
======================`echo $NAME | sed 's/./=/g'`
EOF


#
# Add the site to the PHP config file.
#

cat << EOF >> $OUTPUT

STEP 1
======

Complete the following configuration fragment and add it to 
$PHP_CONF.

You will need to find CFG_COMM_KEY from the corresponding site conf in the
DSNPd configuration file and set it twice.

If you wish to use reCAPTCHA, change USE_RECAPTCHA to true and acquire keys
from the reCAPTCHA project. At present, it will protect new user creation and
friend request. Using reCAPTCHA is optional, but it is strongly recommended
that you use it.

-------- BEGIN FRAGMENT --------

array_push( \$CFG_ARRAY, array(
	'SITE_NAME' => '$NAME DSNP',
	'NAME' => '$NAME',
	'URI' => '$CFG_URI',
	'HOST' => '$CFG_HOST',
	'PATH' => '$CFG_PATH',
	'DB_HOST' => 'localhost',
	'DB_USER' => '${NAME}_ua',
	'DB_DATABASE' => '${NAME}_ua',
	'DB_PASS' => '$CFG_DB_PASS',
	'COMM_KEY' => 'SET_COMM_KEY',
	'PORT' => $CFG_PORT,
	'USE_RECAPTCHA' => false,
	'RC_PUBLIC_KEY' => 'unused',
	'RC_PRIVATE_KEY' => 'unused',
));

-------- END FRAGMENT --------
EOF

#
#sed '/= *site \+s1 *=/,/^ *=/s|^ *CFG_NOTIFICATION.*|CFG_NOTIFICATION = php @datadir@/choicesocialX/web/notification.php|' \
#	$WITH_DSNPD/etc/dsnpd.conf
#
#sed -n '/= *site \+s1 *=/,/^ *=/s|^ *CFG_COMM_KEY *= *\([^ ]\+\) *$|\1|p' \
#	$WITH_DSNPD/etc/dsnpd.conf
#

cat << EOF >> $OUTPUT

STEP 2
======

Create and set permissions on the site's data directory. This is where uploads
go. Run the following script as root.

-------- BEGIN SCRIPT -------

mkdir $LOCALSTATEDIR/lib/choicesocial/$NAME
mkdir $LOCALSTATEDIR/lib/choicesocial/$NAME/data
chown -R ${WWW_USER}:${WWW_USER} $LOCALSTATEDIR/lib/choicesocial/$NAME
chmod 770 $LOCALSTATEDIR/lib/choicesocial/$NAME
chmod 770 $LOCALSTATEDIR/lib/choicesocial/$NAME/data

-------- END SCRIPT -------
EOF

cat << EOF >> $OUTPUT

STEP 3
======

Initialize the database. This step will require the mysql root password. You
may wish to consider copying this fragment to a file and executing it to avoid
putting the database user and pass on your history.

-------- BEGIN SCRIPT -------

mysql -u root -p -B -N -e "
	CREATE USER '${NAME}_ua'@'localhost' IDENTIFIED BY '$CFG_DB_PASS';
	CREATE DATABASE ${NAME}_ua;
	GRANT ALL ON ${NAME}_ua.* TO '${NAME}_ua'@'localhost';

	use ${NAME}_ua;
	source ${DATADIR}/choicesocial/choice.sql;
"

-------- END SCRIPT -------
EOF

cat << EOF >> $OUTPUT

STEP 4
======

Configure Apache to serve the webroot. Go to the webroot for
$CFG_HOST and link:

ln -s $DATADIR/choicesocial/web/webroot .$CFG_PATH

If there is no path on the domain hosting the site, you should go one directory
up and create the link as the directory housing the entire site.
EOF

cat << EOF >> $OUTPUT

STEP 5 
======

Make sure mod_rewrite can work from .htaccess files. Add the following to the
appropriate location or directory.

-------- BEGIN FRAGMENT --------

        AllowOverride FileInfo Options

-------- END FRAGMENT --------


EOF

cat << EOF >> $OUTPUT

STEP 6 (optional)
=================

The DSNP user agent does not work with host aliases. Users must use the primary
site name in their browsers (the one you gave when you specified the site's
URI). It is convenient to setup some redirects. The first is to force SSL and
should be used the conf file for the plain HTTP server.

-------- BEGIN FRAGMENT --------

        RewriteEngine On
        RewriteRule ^/(.*) https://www.site.com/$1 [L,R=permanent]

-------- END FRAGMENT --------

The second is to redirect host aliases to the primary site. It should be used
in the HTTPS site configuration.

-------- BEGIN FRAGMENT --------

        RewriteEngine On
        RewriteCond %{HTTP_HOST}   ^site\.com [NC]
        RewriteRule ^/(.*) https://www.site.com/$1 [L,R=permanent]

-------- END FRAGMENT --------
EOF

echo
echo '**** THANK YOU ****'
echo
echo "Now open '$OUTPUT' and follow the instructions there."
echo
