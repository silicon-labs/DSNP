#!/bin/bash
#
# Copyright (c) 2007, Adrian Thurston <thurston@cs.queensu.ca>
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

echo
echo 'Please choose a username and password to protect this identity'
echo

read -p 'username: ' USER

while true; do
	read -s -p 'password: ' PASS; echo
	read -s -p '   again: ' AGAIN; echo

	if [ "$AGAIN" != "$PASS" ]; then
		echo; echo error: passwords do not match; echo
		continue
	fi

	if [ -z "$AGAIN" ]; then
		echo; echo error: password must not be empty; echo 
		continue
	fi

	break;
done

echo
echo "Please give the Uniform Resource Identifier (URI) of this identity. This"
echo "will be the identity's public name. The URI must resolve to the location"
echo "of this script. It should start with 'http://' and end with '/'."
echo

while true; do 
	read -p 'uri: ' URI

	if echo $URI | grep '^http:\/\/.*\/$' >/dev/null; then
		break
	fi
	echo; echo error: uri did not validate; echo
done 

echo
echo "Thank you, now initializing this identity."
echo

export GNUPGHOME=./gnupghome

# Directory permissions.
chmod 700 $GNUPGHOME
chmod 755 tokens

cat > create-key-cmd <<EOF
Key-Type: DSA
Key-Length: 1024
Subkey-Type: ELG-E
Subkey-Length: 1024
Name-Real: $URI
Expire-Date: 0
%commit
EOF

# Clear the key database and create the key.
rm -Rf $GNUPGHOME/*
gpg --batch --allow-freeform-uid --gen-key create-key-cmd
rm create-key-cmd

# Create the public key file id.asc.
rm -f id.asc
gpg -a -o id.asc --export "$URI"

# Get the fingerprint.
FINGERPRINT=`gpg --fingerprint "$URI" | \
	sed -n '/.ey .ingerprint/{ s/^[^=]*=//; s/[ \t]*//g; p}'`

# Hash the password
PASSHASH=`echo -n $USER:iduri:$PASS | md5sum | awk '{print $1;}'`

cat > config.php << EOF
<?php
/* Configuration */
\$CFG_IDENTITY = '$URI';
\$CFG_FINGERPRINT = '$FINGERPRINT';
\$CFG_USER = '$USER';
\$CFG_PASS = '$PASSHASH';
\$CFG_HTTP_GET_TIMEOUT = 5;

putenv( 'GNUPGHOME=./gnupghome/' );
?>
EOF

php lib/init.php
