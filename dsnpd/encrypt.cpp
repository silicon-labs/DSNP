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
#include "dsnp.h"

#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

int Encrypt::signEncrypt( u_char *msg, long mLen )
{
	RC4_KEY rc4_key;
	u_char *output;

	/* Need to make a buffer containing both the session key and message so we
	 * our signature is valid only using this encryption key. */
	u_char *signData = new u_char[BN_num_bytes(pubEncVer->n) + BN_num_bytes(pubEncVer->e) + mLen];
	BN_bn2bin( pubEncVer->n, signData );
	BN_bn2bin( pubEncVer->e, signData+BN_num_bytes(pubEncVer->n) );
	memcpy( signData + BN_num_bytes(pubEncVer->n) + BN_num_bytes(pubEncVer->e), msg, mLen );

	/* Sign the message. */
	u_char msg_sha1[SHA_DIGEST_LENGTH];
	SHA1( signData, BN_num_bytes(pubEncVer->n) + BN_num_bytes(pubEncVer->e) + mLen, msg_sha1 );

	u_char *signature = (u_char*)malloc( RSA_size(privDecSign) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, msg_sha1, SHA_DIGEST_LENGTH, 
			signature, &sigLen, privDecSign );

	if ( signRes != 1 ) {
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	/* Generate a session key just for this message. */
	unsigned char new_session_key[SK_SIZE];
	RAND_bytes( new_session_key, SK_SIZE );

	/* Encrypt the session key. */
	u_char *encrypted = (u_char*)malloc( RSA_size(pubEncVer) );
	int encLen = RSA_public_encrypt( SK_SIZE, new_session_key, encrypted, 
			pubEncVer, RSA_PKCS1_PADDING );
	
	if ( encLen < 0 ) {
		ERR_error_string( ERR_get_error(), err );
		return encLen;
	}

	u_char *encryptData = new u_char[64 + sigLen + mLen];
	uint16_t *pSigLen = (uint16_t*)encryptData;
	*pSigLen = htons( sigLen );
	long lenLen = 2;
	memcpy( encryptData+lenLen, signature, sigLen );
	memcpy( encryptData+lenLen+sigLen, msg, mLen );

	/* Encrypt the message using the session key. */
	output = (u_char*)malloc( lenLen+sigLen+mLen );
	RC4_set_key( &rc4_key, SK_SIZE, new_session_key );
	RC4( &rc4_key, lenLen+sigLen+mLen, encryptData, output );

	u_char *fullMessage = new u_char[ 2 + encLen + lenLen + sigLen + mLen ];
	uint16_t *pEncLen = (uint16_t*)fullMessage;
	*pEncLen = htons( encLen );
	memcpy( fullMessage + 2, encrypted, encLen );
	memcpy( fullMessage + 2 + encLen, output, lenLen + sigLen + mLen );

	/* FIXME: check results here. */

	sym = binToBase64( fullMessage, 2 + encLen + lenLen + sigLen + mLen );

	free( encrypted );
	free( signature );
	free( output );

	return 0;
}

int Encrypt::decryptVerify( const char *srcMsg )
{
	RC4_KEY rc4_key;
	u_char *data, *signature;
	long dataLen, sigLen;

	/* Convert the message to binary. */
	u_char *message = (u_char*)malloc( strlen(srcMsg) );
	long msgLen = base64ToBin( message, srcMsg, strlen(srcMsg) );
	if ( msgLen <= 0 ) {
		sprintf( err, "error converting hex-encoded message to binary" );
		return -1;
	}

	u_char *encrypted = message + 2;
	uint16_t *pEncSkLen = (uint16_t*)message;
	long encLen = ntohs( *pEncSkLen );
	if ( encLen >= msgLen )
		return -1;
	
	message += 2 + encLen;
	msgLen -= 2 + encLen;

	/* Decrypt the key. */
	u_char *session_key = (u_char*) malloc( RSA_size( privDecSign ) );
	long skLen = RSA_private_decrypt( encLen, encrypted, session_key, 
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

	/* Signature length is in the first two bytes. */
	uint16_t *pSigLen = (uint16_t*)decrypted;
	sigLen = ntohs( *pSigLen );
	if ( sigLen >= msgLen )
		return -1;

	signature = decrypted + 2;
	data = signature + sigLen;
	dataLen = decLen - ( data - decrypted );

	u_char *verifyData = new u_char[BN_num_bytes(privDecSign->n) + BN_num_bytes(privDecSign->e) + dataLen];
	BN_bn2bin( privDecSign->n, verifyData );
	BN_bn2bin( privDecSign->e, verifyData+BN_num_bytes(privDecSign->n) );
	memcpy( verifyData + BN_num_bytes(privDecSign->n) + BN_num_bytes(privDecSign->e), data, dataLen );

	/* Verify the item. */
	u_char decrypted_sha1[SHA_DIGEST_LENGTH];
	SHA1( verifyData, BN_num_bytes(privDecSign->n) + BN_num_bytes(privDecSign->e) + dataLen, decrypted_sha1 );
	int verifyres = RSA_verify( NID_sha1, decrypted_sha1, SHA_DIGEST_LENGTH, 
			signature, sigLen, pubEncVer );
	if ( verifyres != 1 ) {
		ERR_error_string( ERR_get_error(), err );
		return -1;
	}

	decrypted = data;
	decLen = dataLen;

	return 0;
}

int Encrypt::bkSignEncrypt( const char *srcBk, u_char *msg, long mLen )
{
	RC4_KEY rc4_key;
	u_char *output;

	/* Convert the broadcst_key to binary. */
	u_char broadcst_key[SK_SIZE];
	long skLen = base64ToBin( broadcst_key, srcBk, strlen(srcBk) );
	if ( skLen <= 0 ) {
		sprintf( err, "error converting hex-encoded session key string to binary" );
		return -1;
	}

	/* Need to make a buffer containing both the session key and message so we
	 * our signature is valid only using this encryption key. */
	u_char *signData = new u_char[SK_SIZE + mLen];
	memcpy( signData, broadcst_key, SK_SIZE );
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
	uint16_t *pSigLen = (uint16_t*)encryptData;
	*pSigLen = htons( sigLen );
	long lenLen = 2;
	memcpy( encryptData+lenLen, signature, sigLen );
	memcpy( encryptData+lenLen+sigLen, msg, mLen );

	/* Encrypt the message using the session key. */
	output = (u_char*)malloc( lenLen+sigLen+mLen );
	RC4_set_key( &rc4_key, SK_SIZE, broadcst_key );
	RC4( &rc4_key, lenLen+sigLen+mLen, encryptData, output );

	/* FIXME: check results here. */

	sym = binToBase64( output, lenLen+sigLen+mLen );

	free( signature );
	free( output );

	return 0;
}
	
int Encrypt::bkDecryptVerify( const char *srcBk, const char *srcMsg, long srcMsgLen )
{
	RC4_KEY rc4_key;
	u_char *signature, *data;
	long dataLen, sigLen;

	/* Convert the broadcst_key to binary. */
	u_char broadcst_key[SK_SIZE];
	long skLen = base64ToBin( broadcst_key, srcBk, strlen(srcBk) );
	if ( skLen <= 0 ) {
		sprintf( err, "error converting base64-encoded session key string to binary" );
		return -1;
	}

	/* Convert the message to binary. */
	u_char *msg = (u_char*)malloc( srcMsgLen );
	long msgLen = base64ToBin( msg, srcMsg, srcMsgLen );
	if ( msgLen <= 0 ) {
		sprintf( err, "error converting base64-encoded message to binary" );
		return -1;
	}

	decrypted = (u_char*)malloc( msgLen );
	RC4_set_key( &rc4_key, skLen, broadcst_key );
	RC4( &rc4_key, msgLen, msg, decrypted );
	decLen = msgLen;

	/* Signature length is in the first two bytes. */
	uint16_t *pSigLen = (uint16_t*)decrypted;
	sigLen = ntohs( *pSigLen );
	if ( sigLen >= msgLen ) {
		sprintf( err, "sigLen is greater than msgLen" );
		return -1;
	}

	signature = decrypted + 2;
	data = signature + sigLen;
	dataLen = decLen - ( data - decrypted );

	/* Need to make a buffer containing both the session key an message so we
	 * can verify the message was originally signed with this key. */
	u_char *verifyData = new u_char[SK_SIZE + decLen];
	memcpy( verifyData, broadcst_key, SK_SIZE );
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
