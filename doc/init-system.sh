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

function usage()
{
	echo usage: ./init-system.sh instructions-file
	exit 1;
}

# Write config file fragments to this file. It can then be copy-pasted to the
# right places. It will contain instructions.
OUTPUT=$1;
if [ -z "$OUTPUT" ]; then
	usage;
	exit 1;
fi

echo "Please indicate which user the webserver runs as? The dsnpd daemon should be"
echo "run as this user."

while true; do 
	read -p 'user: ' WWW_DATA

	if [ -z "$WWW_DATA" ]; then
		done=yes;
		break;
	fi
	if echo $WWW_DATA | grep '^[a-zA-Z][a-zA-Z0-9_\-]*$' >/dev/null; then
		break
	fi
	echo; echo error: name did not validate; echo
done 

# Clear the output file.
rm -f $OUTPUT;
touch $OUTPUT;
chmod 600 $OUTPUT;

cat << EOF > $OUTPUT
SYSTEM INSTALL INSTRUCTIONS
===========================

1. Ensure that the data and log directories are writable by the user that the
   webserver runs as.

   $ chown ${WWW_DATA}:${WWW_DATA} $PREFIX/var/lib/dsnp
   $ chown ${WWW_DATA}:${WWW_DATA} $PREFIX/var/log/dsnp

2. Add an entry for DSNP to /etc/services. 

   # Local services
   dsnp            7085/tcp

3. Install xinetd. Add a config fragment for DSNPd. Run the server using the
   webserver user. You may wish to adjust the limits.

   service dsnp
   {
       disable          = no
       socket_type      = stream
       protocol         = tcp
       wait             = no
       user             = ${WWW_DATA}
       instances        = 500
       per_source       = 500
       cps              = 1000 1
       server           = ${PREFIX}/bin/dsnpd
   }

4. Install a logrotate fragment.

   ${PREFIX}/var/log/dsnp/*.log {
       weekly
       missingok
       rotate 26
       compress
       delaycompress
       notifempty
       create 640 ${WWW_DATA} ${WWW_DATA}
   }

5. Make the config file for the new-site script. You first need a file
   containing the list of CA certs to trust. This is often avaialable on
   your system. On Ubuntu it is:
   /etc/ssl/certs/ca-certificates.crt

   Change the CA_CERT path and put the following in:
   ${PREFIX}/etc/dsnp-new-site.conf

   CA_CERTS = /path/to/certificate-authority-cert-list.pem
   WWW_USER = ${WWW_DATA}

EOF
