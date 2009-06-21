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
#include <assert.h>

int Encrypt::sign( u_char *src, long len )
{
	/* Sign the src. */
	u_char src_sha1[SHA_DIGEST_LENGTH];
	SHA1( src, len, src_sha1 );

	u_char *signature = (u_char*)malloc( RSA_size(privDecSign) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, src_sha1, SHA_DIGEST_LENGTH, signature, 
			&sigLen, privDecSign );

	if ( signRes != 1 ) {
		free( signature );
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	sig = bin2hex( signature, sigLen );
	free( signature );
	return 0;
}

int Encrypt::verify( u_char *msg, long len, const char *srcSig )
{
	/* Convert the sig to binary. */
	u_char *signature = (u_char*)malloc( strlen(srcSig) );
	long sigLen = hex2bin( signature, strlen(srcSig), srcSig );
	if ( sigLen <= 0 ) {
		sprintf( err, "error converting hex-encoded signature to binary" );
		return -1;
	}

	/* Verify the item. */
	u_char msg_sha1[SHA_DIGEST_LENGTH];
	SHA1( msg, len, msg_sha1 );
	int verifyres = RSA_verify( NID_sha1, msg_sha1, SHA_DIGEST_LENGTH, 
			signature, sigLen, pubEncVer );
	if ( verifyres != 1 ) {
		error("verification failed\n");
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	return 0;
}

int Encrypt::signEncrypt( u_char *msg, long mLen )
{
	/* Need to make a buffer containing both the session key and message so we
	 * our signature is valid only using this encryption key. */
	u_char *signData = new u_char[BN_num_bytes(pubEncVer->n) + BN_num_bytes(pubEncVer->e) + mLen];
	BN_bn2bin( pubEncVer->n, signData );
	BN_bn2bin( pubEncVer->e, signData+BN_num_bytes(pubEncVer->n) );
	memcpy( signData + BN_num_bytes(pubEncVer->n) + BN_num_bytes(pubEncVer->e), msg, mLen );

	/* Sign the msg. */
	u_char src_sha1[SHA_DIGEST_LENGTH];
	SHA1( signData, BN_num_bytes(pubEncVer->n) + BN_num_bytes(pubEncVer->e) + mLen, src_sha1 );

	u_char *signature = (u_char*)malloc( RSA_size(privDecSign) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, src_sha1, SHA_DIGEST_LENGTH, signature, 
			&sigLen, privDecSign );

	if ( signRes != 1 ) {
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	/* Encrypt the src. */
	u_char *encrypted = (u_char*)malloc( RSA_size(pubEncVer) );
	int encLen = RSA_public_encrypt( mLen, msg, encrypted, 
			pubEncVer, RSA_PKCS1_PADDING );
	
	if ( encLen < 0 ) {
		ERR_error_string( ERR_get_error(), err );
		return encLen;
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
	long encLen = hex2bin( encrypted, strlen(srcEnc), srcEnc );
	if ( encLen <= 0 ) {
		sprintf( err, "error converting hex-encoded encrypted string to binary" );
		return -1;
	}

	/* Convert the sig to binary. */
	u_char *signature = (u_char*)malloc( strlen(srcSig) );
	long sigLen = hex2bin( signature, strlen(srcSig), srcSig );
	if ( sigLen <= 0 ) {
		sprintf( err, "error converting hex-encoded signature to binary" );
		return -1;
	}

	/* Decrypt the item. */
	decrypted = (u_char*) malloc( RSA_size( privDecSign ) );
	decLen = RSA_private_decrypt( encLen, encrypted, decrypted, 
			privDecSign, RSA_PKCS1_PADDING );
	if ( decLen < 0 ) {
		error("decryption failed\n");
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	u_char *verifyData = new u_char[BN_num_bytes(privDecSign->n) + BN_num_bytes(privDecSign->e) + decLen];
	BN_bn2bin( privDecSign->n, verifyData );
	BN_bn2bin( privDecSign->e, verifyData+BN_num_bytes(privDecSign->n) );
	memcpy( verifyData + BN_num_bytes(privDecSign->n) + BN_num_bytes(privDecSign->e), decrypted, decLen );

	/* Verify the item. */
	u_char decrypted_sha1[SHA_DIGEST_LENGTH];
	SHA1( verifyData, BN_num_bytes(privDecSign->n) + BN_num_bytes(privDecSign->e) + decLen, decrypted_sha1 );
	int verifyres = RSA_verify( NID_sha1, decrypted_sha1, SHA_DIGEST_LENGTH, 
			signature, sigLen, pubEncVer );
	if ( verifyres != 1 ) {
		error("verification failed\n");
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	return 0;
}
	
int Encrypt::symSignEncrypt( u_char *message, long len )
{
	RC4_KEY rc4_key;
	u_char *output;

	/* Generate a session key just for this message. */
	unsigned char new_sesion_key[SK_SIZE];
	RAND_bytes( new_sesion_key, SK_SIZE );

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

int Encrypt::skSignEncrypt( const char *srcSK, u_char *msg, long mLen )
{
	RC4_KEY rc4_key;
	u_char *output;

	/* Convert the session_key to binary. */
	u_char session_key[SK_SIZE];
	long skLen = hex2bin( session_key, SK_SIZE, srcSK );
	if ( skLen <= 0 ) {
		sprintf( err, "error converting hex-encoded session key string to binary" );
		return -1;
	}

	/* Need to make a buffer containing both the session key and message so we
	 * our signature is valid only using this encryption key. */
	u_char *signData = new u_char[SK_SIZE + mLen];
	memcpy( signData, session_key, SK_SIZE );
	memcpy( signData+SK_SIZE, msg, mLen );

	/* Sign the message. */
	u_char msg_sha1[SHA_DIGEST_LENGTH];
	SHA1( signData, SK_SIZE+mLen, msg_sha1 );

	u_char *signature = (u_char*)malloc( RSA_size(privDecSign) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, msg_sha1, SHA_DIGEST_LENGTH, 
			signature, &sigLen, privDecSign );

	if ( signRes != 1 ) {
		free( signature );
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	u_char *encryptData = new u_char[64 + sigLen + mLen];
	long lenLen = sprintf( (char*)encryptData, "%d\n", sigLen );
	memcpy( encryptData+lenLen, signature, sigLen );
	memcpy( encryptData+lenLen+sigLen, msg, mLen );

	::message( "size1: %d %d %d\n", lenLen, sigLen, mLen );

	/* Encrypt the message using the session key. */
	output = (u_char*)malloc( lenLen+sigLen+mLen );
	RC4_set_key( &rc4_key, SK_SIZE, session_key );
	RC4( &rc4_key, lenLen+sigLen+mLen, encryptData, output );

	/* FIXME: check results here. */

	sig = bin2hex( signature, sigLen );
	sym = bin2hex( output, lenLen+sigLen+mLen );

	free( signature );
	free( output );

	return 0;
}
	
int Encrypt::skDecryptVerify( const char *srcSK, const char *srcMsg )
{
	RC4_KEY rc4_key;
	u_char *signature, *data;
	long dataLen, sigLen;

	/* Convert the session_key to binary. */
	u_char session_key[SK_SIZE];
	long skLen = hex2bin( session_key, SK_SIZE, srcSK );
	if ( skLen <= 0 ) {
		sprintf( err, "error converting hex-encoded session key string to binary" );
		return -1;
	}

	/* Convert the message to binary. */
	u_char *msg = (u_char*)malloc( strlen(srcMsg) );
	long msgLen = hex2bin( msg, strlen(srcMsg), srcMsg );
	if ( msgLen <= 0 ) {
		sprintf( err, "error converting hex-encoded message to binary" );
		return -1;
	}

	decrypted = (u_char*)malloc( msgLen );
	RC4_set_key( &rc4_key, skLen, session_key );
	RC4( &rc4_key, msgLen, msg, decrypted );
	decLen = msgLen;

	/* FIXME: ragel scanner that verifies resulting lengths. */
	sscanf( (char*)decrypted, "%ld\n", &sigLen );
	signature = (u_char*) strchr( (char*)decrypted, '\n' ) + 1;
	data = signature + sigLen;
	dataLen = decLen - ( data - decrypted );

	/* Need to make a buffer containing both the session key an message so we
	 * can verify the message was originally signed with this key. */
	u_char *verifyData = new u_char[SK_SIZE + decLen];
	memcpy( verifyData, session_key, SK_SIZE );
	memcpy( verifyData+SK_SIZE, data, dataLen );

	/* Verify the message. */
	u_char decrypted_sha1[SHA_DIGEST_LENGTH];
	SHA1( verifyData, SK_SIZE+dataLen, decrypted_sha1 );
	int verifyres = RSA_verify( NID_sha1, decrypted_sha1, SHA_DIGEST_LENGTH, 
			signature, sigLen, pubEncVer );
	if ( verifyres != 1 ) {
		message("verify failed\n");
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	decrypted = data;
	decLen = dataLen;

	return 0;
}
