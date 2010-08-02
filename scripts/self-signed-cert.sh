#!/bin/bash
#

CN=$1

if ! [ -n "$CN" ]; then
	echo no cert name given
	exit 1;
fi

openssl genrsa -out $CN.key 1024
openssl req -new -key $CN.key -out $CN.csr
openssl x509 -req -days 365 -in $CN.csr -signkey $CN.key -out $CN.crt


