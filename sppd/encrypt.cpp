/*
 * Copyright (c) 2009, Adrian Thurston <thurston@complang.org>
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

#include "encrypt.h"
#include "sppd.h"

#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

int Encrypt::encryptSign( u_char *src, long len )
{
	/* Encrypt the src. */
	u_char *encrypted = (u_char*)malloc( RSA_size(pubEncVer) );
	int encLen = RSA_public_encrypt( len, src, encrypted, 
			pubEncVer, RSA_PKCS1_PADDING );
	
	if ( encLen < 0 ) {
		free( encrypted );
		ERR_error_string( ERR_get_error(), err );
		return encLen;
	}

	/* Sign the src. */
	u_char src_sha1[SHA_DIGEST_LENGTH];
	SHA1( src, len, src_sha1 );

	u_char *signature = (u_char*)malloc( RSA_size(privDecSign) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, src_sha1, SHA_DIGEST_LENGTH, signature, 
			&sigLen, privDecSign );

	if ( signRes != 1 ) {
		free( encrypted );
		free( signature );
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	enc = bin2hex( encrypted, encLen );
	sig = bin2hex( signature, sigLen );

	free( encrypted );
	free( signature );

	return 0;
}

int Encrypt::decryptVerify( const char *srcEnc, const char *srcSig )
{
	/* Convert the encrypted string to binary. */
	u_char *encrypted = (u_char*)malloc( strlen(srcEnc) );
	long encLen = hex2bin( encrypted, RSA_size(pubEncVer), srcEnc );
	if ( encLen <= 0 ) {
		sprintf( err, "error converting hex-encoded encrypted string to binary" );
		return -1;
	}

	/* Convert the sig to binary. */
	u_char *signature = (u_char*)malloc( strlen(srcSig) );
	long sigLen = hex2bin( signature, RSA_size(pubEncVer), srcSig );
	if ( sigLen <= 0 ) {
		sprintf( err, "error converting hex-encoded signature to binary" );
		return -1;
	}

	/* Decrypt the item. */
	decrypted = (u_char*) malloc( RSA_size( privDecSign ) );
	decLen = RSA_private_decrypt( encLen, encrypted, decrypted, 
			privDecSign, RSA_PKCS1_PADDING );
	if ( decLen < 0 ) {
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	/* Verify the item. */
	u_char decrypted_sha1[SHA_DIGEST_LENGTH];
	SHA1( decrypted, RELID_SIZE, decrypted_sha1 );
	int verifyres = RSA_verify( NID_sha1, decrypted_sha1, SHA_DIGEST_LENGTH, 
			signature, sigLen, pubEncVer );
	if ( verifyres != 1 ) {
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	return 0;
}
	
int Encrypt::symEncryptSign( u_char *message, long len )
{
	RC4_KEY rc4_key;
	u_char *output;

	/* Generate a session key just for this message. */
	unsigned char new_sesion_key[SK_SIZE];
	RAND_bytes( new_sesion_key, SK_SIZE );

	printf("symEncryptSign session_key: %s\n", bin2hex( new_sesion_key, SK_SIZE ) );

	/* Encrypt the session key. */
	u_char *encrypted = (u_char*)malloc( RSA_size(pubEncVer) );
	int encLen = RSA_public_encrypt( SK_SIZE, new_sesion_key, encrypted, 
			pubEncVer, RSA_PKCS1_PADDING );
	
	if ( encLen < 0 ) {
		free( encrypted );
		ERR_error_string( ERR_get_error(), err );
		return encLen;
	}

	/* Encrypt the message using the session key. */
	output = (u_char*)malloc( len );
	RC4_set_key( &rc4_key, SK_SIZE, new_sesion_key );
	RC4( &rc4_key, len, message, output );

	/* FIXME: check results here. */

	/* Sign the message. */
	u_char msg_sha1[SHA_DIGEST_LENGTH];
	SHA1( message, len, msg_sha1 );

	u_char *signature = (u_char*)malloc( RSA_size(privDecSign) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, msg_sha1, SHA_DIGEST_LENGTH, 
			signature, &sigLen, privDecSign );

	if ( signRes != 1 ) {
		free( encrypted );
		free( signature );
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	enc = bin2hex( encrypted, encLen );
	sig = bin2hex( signature, sigLen );
	sym = bin2hex( output, len );

	free( encrypted );
	free( signature );
	free( output );

	return 0;
}

int Encrypt::symDecryptVerify( const char *srcEnc, const char *srcSig, const char *srcMsg )
{
	RC4_KEY rc4_key;

	/* Convert the encrypted string to binary. */
	u_char *encrypted = (u_char*)malloc( strlen(srcEnc) );
	long encLen = hex2bin( encrypted, RSA_size(pubEncVer), srcEnc );
	if ( encLen <= 0 ) {
		sprintf( err, "error converting hex-encoded encrypted string to binary" );
		return -1;
	}

	/* Convert the sig to binary. */
	u_char *signature = (u_char*)malloc( strlen(srcSig) );
	long sigLen = hex2bin( signature, RSA_size(pubEncVer), srcSig );
	if ( sigLen <= 0 ) {
		sprintf( err, "error converting hex-encoded signature to binary" );
		return -1;
	}

	/* Convert the message to binary. */
	u_char *message = (u_char*)malloc( strlen(srcMsg) );
	long msgLen = hex2bin( message, strlen(srcMsg), srcMsg );
	if ( msgLen <= 0 ) {
		sprintf( err, "error converting hex-encoded message to binary" );
		return -1;
	}

	/* Decrypt the key. */
	session_key = (u_char*) malloc( RSA_size( privDecSign ) );
	skLen = RSA_private_decrypt( encLen, encrypted, session_key, 
			privDecSign, RSA_PKCS1_PADDING );
	if ( skLen < 0 ) {
		sprintf( err, "bad session key");
		//ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	decrypted = (u_char*)malloc( msgLen );
	RC4_set_key( &rc4_key, skLen, session_key );
	RC4( &rc4_key, msgLen, message, decrypted );
	decLen = msgLen;

	/* Verify the message. */
	u_char decrypted_sha1[SHA_DIGEST_LENGTH];
	SHA1( decrypted, msgLen, decrypted_sha1 );
	int verifyres = RSA_verify( NID_sha1, decrypted_sha1, SHA_DIGEST_LENGTH, 
			signature, sigLen, pubEncVer );
	if ( verifyres != 1 ) {
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	return 0;
}
	
