#!/bin/bash
#
# Copyright (c) 2007-2010, Adrian Thurston <thurston@complang.org>
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

DSNPD_CONF=@sysconfdir@/dsnpd.conf
PHP_CONF=@sysconfdir@/dsnpua.php
DATADIR=@datadir@
LOCALSTATEDIR=@localstatedir@
SYSCONFDIR=@sysconfdir@
PREFIX=@prefix@

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

# Read the new-site config file.
{
	while read name eq value; do
		eval $name=$value;
	done
} < ${PREFIX}/etc/dsnp-new-site.conf


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
echo "names. It will not be visible to any user of the site."
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

CFG_HOST=`echo $URI_IN | sed 's|^https://||; s|/.*$||; s|/$||'`
CFG_URI=$URI_IN;
CFG_PATH=`echo $URI_IN | sed 's|^https://||; s|^[^/]*||; s|/$||'`

# Make a key for communication from the frontend to backend.
CFG_COMM_KEY=`head -c 24 < /dev/urandom | xxd -p`

echo
echo Please choose a password to protect the new database user with. 
echo

while true; do
	read -s -p 'password: ' CFG_DB_PASS; echo
	read -s -p '   again: ' AGAIN; echo

	if [ "$CFG_DB_PASS" != "$AGAIN" ]; then
		echo; echo error: passwords do not match; echo
		continue
	fi

	if [ -z "$CFG_DB_PASS" ]; then
		echo; echo error: password must not be empty; echo 
		continue
	fi
	break;
done

#
# Add the site to the dsnpd config file.
#

cat << EOF > $OUTPUT
INSTALL INSTRUCTIONS: $NAME
======================`echo $NAME | sed 's/./=/g'`
EOF

#
# The Certificates
#

cat << EOF >> $OUTPUT

STEP 1
======

Acquire and install the site's certificate and key file.

The key file you should have generated yourself. The certificate was issued to
you. If there is a chain, add the certs to the end (your cert first, then
append certs as you go up the chain).

KEY_FILE=/path/to/private-key.key
CRT_FILE=/path/to/certificate.crt

-------- BEGIN SCRIPT -------

cp \$KEY_FILE $SYSCONFDIR/dsnp-ssl/$NAME.key
cp \$CRT_FILE $SYSCONFDIR/dsnp-ssl/$NAME.crt
chown ${WWW_USER}:${WWW_USER} \\
      $SYSCONFDIR/dsnp-ssl/$NAME.key \\
      $SYSCONFDIR/dsnp-ssl/$NAME.crt 
chmod 600 \\
      $SYSCONFDIR/dsnp-ssl/$NAME.key \\
      $SYSCONFDIR/dsnp-ssl/$NAME.crt 

-------- END SCRIPT -------

If this is a testing installation that will only communicate with itself, you
can generate a self-signed cert and use it as the CFG_TLS_CA_CERTS in the next step.
EOF

#
# The dsnpd.conf file
#

cat << EOF >> $OUTPUT

STEP 2
======
Once the cert section is complete, add the configuration fragment to
$DSNPD_CONF

-------- BEGIN FRAGMENT --------

===== $NAME =====

CFG_URI = $CFG_URI
CFG_HOST = $CFG_HOST
CFG_PATH = $CFG_PATH
CFG_DB_HOST = localhost
CFG_DB_USER = ${NAME}
CFG_DB_DATABASE = ${NAME}
CFG_DB_PASS = $CFG_DB_PASS
CFG_COMM_KEY = $CFG_COMM_KEY
CFG_PORT = $CFG_PORT
CFG_TLS_CA_CERTS = ${CA_CERTS}
CFG_TLS_CRT = $SYSCONFDIR/dsnp-ssl/$NAME.crt
CFG_TLS_KEY = $SYSCONFDIR/dsnp-ssl/$NAME.key

-------- END FRAGMENT --------
EOF


#
# Add the site to the PHP config file.
#

cat << EOF >> $OUTPUT

STEP 3
======

Add the following configuration fragment to $PHP_CONF

-------- BEGIN FRAGMENT --------

if ( strpos( \$_SERVER['HTTP_HOST'] . \$_SERVER['REQUEST_URI'], 
		'$CFG_HOST$CFG_PATH' ) === 0 )
{
	\$CFG['SITE_NAME'] = '$NAME DSNP';
	\$CFG['NAME'] = '$NAME';
	\$CFG['URI'] = '$CFG_URI';
	\$CFG['HOST'] = '$CFG_HOST';
	\$CFG['PATH'] = '$CFG_PATH';
	\$CFG['DB_HOST'] = 'localhost';
	\$CFG['DB_USER'] = '${NAME}';
	\$CFG['DB_DATABASE'] = '${NAME}';
	\$CFG['DB_PASS'] = '$CFG_DB_PASS';
	\$CFG['COMM_KEY'] = '$CFG_COMM_KEY';
	\$CFG['PORT'] = $CFG_PORT;

	\$CFG['IM_CONVERT'] = 'gm convert';
	\$CFG['USE_RECAPTCHA'] = false;
	\$CFG['RC_PUBLIC_KEY'] = 'unused';
	\$CFG['RC_PRIVATE_KEY'] = 'unused';
}

-------- END FRAGMENT --------
EOF

cat << EOF >> $OUTPUT

STEP 4 (optional)
=================

Set up reCAPTCHA. This step is optional, however, it is strongly recommended
that you complete it. Change USE_RECAPTCHA in the config file to true, acquire
keys from reCAPTCHA, and set them in the config file.
EOF

cat << EOF >> $OUTPUT

STEP 5
======

Create and set permissions on the site's data directory. This is where uploads
go. Run the following script as root.

-------- BEGIN SCRIPT -------

mkdir $LOCALSTATEDIR/lib/dsnp/$NAME
mkdir $LOCALSTATEDIR/lib/dsnp/$NAME/data
chown -R ${WWW_USER}:${WWW_USER} $LOCALSTATEDIR/lib/dsnp/$NAME

-------- END SCRIPT -------
EOF

cat << EOF >> $OUTPUT

STEP 6
======

Initialize the database. This step will require the mysql root password. You
may wish to consider copying this fragment to a file and executing it to avoid
putting the database user and pass on your history.

-------- BEGIN SCRIPT -------

mysql -u root -p -B -N -e "
	CREATE USER '${NAME}'@'localhost' IDENTIFIED BY '$CFG_DB_PASS';
	CREATE DATABASE ${NAME};
	GRANT ALL ON ${NAME}.* TO '${NAME}'@'localhost';
"

mysql -u $NAME -p'$CFG_DB_PASS' $NAME < $DATADIR/dsnp/init.sql

-------- END SCRIPT -------
EOF

cat << EOF >> $OUTPUT

STEP 7
======

Configure Apache to serve the weboot. Go to the webroot for
$CFG_HOST and link:

ln -s $DATADIR/dsnp/web/webroot .$CFG_PATH

If there is no path on the domain hosting the site, you should go one directory
up and create the link as the directory housing the entire site.
EOF

cat << EOF >> $OUTPUT

STEP 8 
======

Make sure mod_rewrite can work from .htaccess files. Add the following to the
appropriate location or directory.

-------- BEGIN FRAGMENT --------

        AllowOverride FileInfo Options

-------- END FRAGMENT --------


EOF

cat << EOF >> $OUTPUT

STEP 9 (optional)
=================

The DSNP user agent does not work with host aliases. Users must use the primary
site name in their browsers (the one you gave when you specified the site's
URI). IT is convenient to setup some redirects. The first is to force SSL and
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
