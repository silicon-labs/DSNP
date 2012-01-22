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

DSNPD_CONF=@sysconfdir@/dsnpd.conf
DATADIR=@datadir@
LOCALSTATEDIR=@localstatedir@
SYSCONFDIR=@sysconfdir@
PREFIX=@prefix@
DSNPD_USER=@DSNPD_USER@

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
echo "identify the site. It will not be visible to any user of the site."
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
echo "Please give the public host name of the site"
echo "(identical to host name in users)."
echo

while true; do 
	read -p 'installation host name: ' HOST_IN

	if echo $HOST_IN | grep '^[a-zA-Z0-9.\-]\+$' >/dev/null; then
		break
	fi
	echo; echo error: host name did not validate; echo
done 

CFG_HOST="$HOST_IN"

# Make a key for communication from the frontend to backend.
CFG_COMM_KEY=`head -c 24 < /dev/urandom | xxd -p`

# Make passwords.
CFG_DB_PASS1=`head -c 8 < /dev/urandom | xxd -p`
CFG_DB_PASS2=`head -c 8 < /dev/urandom | xxd -p`

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

cp \$KEY_FILE $SYSCONFDIR/dsnpd-ssl/$NAME.key
cp \$CRT_FILE $SYSCONFDIR/dsnpd-ssl/$NAME.crt
chown ${DSNPD_USER}:${DSNPD_USER} \\
      $SYSCONFDIR/dsnpd-ssl/$NAME.key \\
      $SYSCONFDIR/dsnpd-ssl/$NAME.crt 
chmod 600 \\
      $SYSCONFDIR/dsnpd-ssl/$NAME.key \\
      $SYSCONFDIR/dsnpd-ssl/$NAME.crt 

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

Complete the following fragment by setting the notification script and add it
to $DSNPD_CONF.

If this host has already been added then it should be skipped.

-------- BEGIN FRAGMENT --------

===== host =====

CFG_HOST = $CFG_HOST
CFG_TLS_CRT = $SYSCONFDIR/dsnpd-ssl/$NAME.crt
CFG_TLS_KEY = $SYSCONFDIR/dsnpd-ssl/$NAME.key

===== site $NAME =====

CFG_COMM_KEY = $CFG_COMM_KEY
CFG_NOTIFICATION = php /path/to/notification.php

-------- END FRAGMENT --------
EOF


echo
echo '**** THANK YOU ****'
echo
echo "Now open '$OUTPUT' and follow the instructions there."
echo
