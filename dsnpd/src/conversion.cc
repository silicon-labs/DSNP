/*
 * Copyright (c) 2008-2011, Adrian Thurston <thurston@complang.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "dsnp.h"
#include "encrypt.h"
#include "string.h"
#include "error.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include <openssl/pem.h>
#include <openssl/err.h>

char *bin2hex( unsigned char *data, long len )
{
	char *res = (char*)malloc( len*2 + 1 );
	for ( int i = 0; i < len; i++ ) {
		unsigned char l = data[i] & 0xf;
		if ( l < 10 )
			res[i*2+1] = '0' + l;
		else
			res[i*2+1] = 'a' + (l-10);

		unsigned char h = data[i] >> 4;
		if ( h < 10 )
			res[i*2] = '0' + h;
		else
			res[i*2] = 'a' + (h-10);
	}
	res[len*2] = 0;
	return res;
}

long hex2bin( unsigned char *dest, long len, const char *src )
{
	long slen = strlen( src ) / 2;
	if ( len < slen )
		return 0;
	
	for ( int i = 0; i < slen; i++ ) {
		char l = src[i*2+1];
		char h = src[i*2];

		if ( '0' <= l && l <= '9' )
			dest[i] = l - '0';
		else
			dest[i] = 10 + (l - 'a');
			
		if ( '0' <= h && h <= '9' )
			dest[i] |= (h - '0') << 4;
		else
			dest[i] |= (10 + (h - 'a')) << 4;
	}
	return slen;
}

Allocated bnToBase64( const BIGNUM *n )
{
	long len = BN_num_bytes(n);
	u_char *bin = new u_char[len];
	BN_bn2bin( n, bin );
	Allocated b64 = binToBase64( bin, len );
	delete[] bin;
	return b64;
}

Allocated bnToBin( const BIGNUM *n )
{
	long len = BN_num_bytes(n);
	u_char *bin = new u_char[len+1];
	BN_bn2bin( n, bin );
	bin[len] = 0;
	return Allocated( (char*)bin, len );
}

BIGNUM *base64ToBn( const char *base64 )
{
	String bin = base64ToBin( base64, strlen(base64) );
	BIGNUM *bn = BN_bin2bn( bin.binary(), bin.length, 0 );
	return bn;
}

BIGNUM *binToBn( const String &bin )
{
	BIGNUM *bn = BN_bin2bn( bin.binary(), bin.length, 0 );
	return bn;
}

long long parseId( const char *id )
{
	/* FIXME: overflow check. */
	return strtoll( id, 0, 10 );
}

bool parseBoolean( const char *b )
{
	return strcmp( b, "1" ) == 0;
}

long parseLength( const char *length )
{
	/* FIXME: overflow check. */
	return strtol( length, 0, 10 );
}

Allocated passHash( const u_char *salt, const char *pass )
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	u_char *combined = new u_char[SALT_SIZE + strlen(pass)];
	memcpy( combined, salt, SALT_SIZE );
	memcpy( combined + SALT_SIZE, pass, strlen(pass) );
	SHA1( combined, SALT_SIZE+strlen(pass), hash );
	return binToBase64( hash, SHA_DIGEST_LENGTH );
}

Allocated makeIduriHash( const char *identity )
{
	/* Make a hash for the identity. */
	unsigned char hash[SHA_DIGEST_LENGTH];
	String lower = Pointer( identity );
	lower.toLower();
	SHA1( lower.binary(), lower.length, hash );
	return binToBase64( hash, SHA_DIGEST_LENGTH );
}

Allocated sha1( const String &src )
{
	/* Make a hash for the identity. */
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1( src.binary(), src.length, hash );
	return binToBase64( hash, SHA_DIGEST_LENGTH );
}
