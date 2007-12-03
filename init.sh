#!/bin/bash

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
\$IDENTITY = '$URI';
\$FINGERPRINT = '$FINGERPRINT';
\$USER = '$USER';
\$PASS = '$PASSHASH';
?>
EOF

php << EOF
<?php
include( 'config.php' );
include( 'lib/iduri.php' );
initDB( );
?>
EOF


