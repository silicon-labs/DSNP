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

# Make passwords.
CFG_DB_PASS1=`head -c 8 < /dev/urandom | xxd -p`
CFG_DB_PASS2=`head -c 8 < /dev/urandom | xxd -p`
CFG_DB_PASS3=`head -c 8 < /dev/urandom | xxd -p`

# Port for the server.
CFG_PORT=7085

cat << EOF > $OUTPUT

SYSTEM INSTALL INSTRUCTIONS
===========================
EOF

cat << EOF >> $OUTPUT

STEP 1
======

Set permissions on various files and directories. This must be run as root.

-------- BEGIN SCRIPT -------

install -d @prefix@/var/log/dsnpd
install -d @prefix@/etc/dsnpd-ssl
chown root:root @sysconfdir@/dsnpd.conf
chown root:root @sysconfdir@/dsnpd-ssl
chmod 600 @sysconfdir@/dsnpd.conf
chmod 700 @sysconfdir@/dsnpd-ssl
chown root:root @prefix@/var/log/dsnpd
chmod 700 @prefix@/var/log/dsnpd

-------- END SCRIPT -------
EOF

cat << EOF >> $OUTPUT

STEP 2
======

Install a logrotate fragment.

   @prefix@/var/log/dsnp/dsnpd.log
   @prefix@/var/log/dsnp/dsnpk.log
   @prefix@/var/log/dsnp/dsnpn.log
   {
       weekly
       missingok
       rotate 26
       compress
       delaycompress
       notifempty
       create 600 root root
       sharedscripts
       postrotate
           if test -f @PID_DIR@/dsnpd.pid; then
               kill -HUP "\`cat @PID_DIR@/dsnpd.pid\`"
	   fi
       endscript
   }
EOF

cat << EOF >> $OUTPUT

STEP 3
======

Install the init script from the share directory. The manner of installing this
will be system dependent.
EOF

#
# dsnpd.conf file.
#

cat << EOF >> $OUTPUT

STEP 4
======

Complete the following fragment by setting the notification script and add it
to $DSNPD_CONF

-------- BEGIN FRAGMENT --------

#
# Daemon
#
CFG_PORT = $CFG_PORT
CFG_DB_HOST = localhost
CFG_DB_USER = dsnpd
CFG_DB_DATABASE = dsnpd
CFG_DB_PASS = $CFG_DB_PASS1

#
# Key Agent.
#
CFG_KEYS_HOST = localhost
CFG_KEYS_USER = dsnpk
CFG_KEYS_DATABASE = dsnpk
CFG_KEYS_PASS = $CFG_DB_PASS2

#
# Notification Agent.
#
CFG_NOTIF_HOST = localhost
CFG_NOTIF_KEYS_USER = dsnpn
CFG_NOTIF_DATABASE = dsnpn
CFG_NOTIF_PASS = $CFG_DB_PASS3

-------- END FRAGMENT --------
EOF


#
# Database initialization
#

cat << EOF >> $OUTPUT

STEP 5
======

Initialize the database. This step will require the mysql root password. You
may wish to consider copying this fragment to a file and executing it to avoid
putting the database user and pass on your history.

-------- BEGIN SCRIPT -------

mysql -u root -p -B -N -e "
	CREATE USER 'dsnpd'@'localhost' IDENTIFIED BY '$CFG_DB_PASS1';
	CREATE DATABASE dsnpd;
	GRANT ALL ON dsnpd.* TO 'dsnpd'@'localhost';

	CREATE USER 'dsnpk'@'localhost' IDENTIFIED BY '$CFG_DB_PASS2';
	CREATE DATABASE dsnpk;
	GRANT ALL ON dsnpk.* TO 'dsnpk'@'localhost';

	CREATE USER 'dsnpn'@'localhost' IDENTIFIED BY '$CFG_DB_PASS3';
	CREATE DATABASE dsnpn;
	GRANT ALL ON dsnpn.* TO 'dsnpn'@'localhost';

	USE dsnpd;
	SOURCE ${DATADIR}/dsnpd/dsnpd.sql;

	USE dsnpk;
	SOURCE ${DATADIR}/dsnpd/dsnpk.sql

	USE dsnpn;
	SOURCE ${DATADIR}/dsnpd/dsnpn.sql
"

-------- END SCRIPT -------
EOF

