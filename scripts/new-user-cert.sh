#!/bin/bash
#

# Path prefix
CN=$1
PP=$2

# Needed because the site name is in the path and is is not installed.
mkdir -p `dirname $PP`

# There shouldn't be anything there.
rm -f $PP.*

# Generate key.
openssl genrsa -out $PP.key 1024

# Certificate signing request.
openssl req -new \
	-subj "/CN=$CN/" \
	-key $PP.key -out $PP.csr

# Self-signed certificate.
openssl x509 -req -days 365 \
	-in $PP.csr \
	-signkey $PP.key \
	-out $PP.crt
