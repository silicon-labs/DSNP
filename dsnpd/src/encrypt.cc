/*
 * Copyright (c) 2009-2011, Adrian Thurston <thurston@complang.org>
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
#include "packet.h"
#include "dsnp.h"
#include "error.h"

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

Allocated signEncrypt( Keys *pubEncVer, Keys *privDecSign, const String *iduri, const String &msg )
{
	/* Need to make a buffer containing both the session key and message so we
	 * our signature is valid only using this encryption key. */
	String nBin = bnToBin( pubEncVer->rsa->n );
	String eBin = bnToBin( pubEncVer->rsa->e );
	String signData = concatenate( 3, &nBin, &eBin, &msg );

	/* Sign the message. */
	u_char msgSha1[SHA_DIGEST_LENGTH];
	SHA1( signData.binary(), signData.length, msgSha1 );

	String sigBin( RSA_size(privDecSign->rsa) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, msgSha1, SHA_DIGEST_LENGTH, 
			sigBin.binary(), &sigLen, privDecSign->rsa );

	if ( signRes != 1 )
		throw RsaSignFailed( ERR_get_error() );

	/* Generate a session key just for this message. */
	unsigned char keyBin[SK_SIZE];
	RAND_bytes( keyBin, SK_SIZE );
	
	/* Encrypt the session key. */
	String protKey( RSA_size(pubEncVer->rsa) );
	int protKeyLen = RSA_public_encrypt( SK_SIZE, keyBin, protKey.binary(), 
			pubEncVer->rsa, RSA_PKCS1_PADDING );

	if ( protKeyLen < 0 )
		throw RsaPublicEncryptFailed( ERR_get_error() );

	/*
	 * Concatenate the signature and the message so we can encrypt it.
	 */
	
	/* Make the concatenated plain text. FIXME: this is a bit of an abuse. The
	 * sig does not apply to msg alone. */
	String plainData = iduri == 0 ? 
			consSigned( sigBin, msg ) :
			consSignedId( *iduri, sigBin, msg );

	/* Encrypt using the session key. */
	String enc( plainData.length );
	RC4_KEY rc4Key;
	RC4_set_key( &rc4Key, SK_SIZE, keyBin );
	RC4( &rc4Key, plainData.length, plainData.binary(), enc.binary() );

	/* Result. */
	String encPacket = consSignedEncrypted( protKey, enc );

	return encPacket.relinquish();
}

Allocated decryptVerify( Keys *pubEncVer, Keys *privDecSign, const String &msg )
{
	PacketSignedEncrypted epp1( msg );

	/* Decrypt the key. */
	String sessionKey( RSA_size( privDecSign->rsa ) );
	long skLen = RSA_private_decrypt( epp1.protKey.length, epp1.protKey.binary(),
			sessionKey.binary(), privDecSign->rsa, RSA_PKCS1_PADDING );
	if ( skLen < 0 )
		throw RsaPrivateDecryptFailed( ERR_get_error() );

	String dec( epp1.enc.length );
	RC4_KEY rc4Key;
	RC4_set_key( &rc4Key, skLen, sessionKey.binary() );
	RC4( &rc4Key, epp1.enc.length, epp1.enc.binary(), dec.binary() );

	PacketSigned epp2( dec );

	String nBin = bnToBin( privDecSign->rsa->n );
	String eBin = bnToBin( privDecSign->rsa->e );
	String verifyData = concatenate( 3, &nBin, &eBin, &epp2.msg );

	/* Verify the item. */
	u_char decryptedSha1[SHA_DIGEST_LENGTH];
	SHA1( verifyData.binary(), verifyData.length, decryptedSha1 );
	int verifyres = RSA_verify( NID_sha1, decryptedSha1, SHA_DIGEST_LENGTH, 
			epp2.sig.binary(), epp2.sig.length, pubEncVer->rsa );
	if ( verifyres != 1 )
		throw RsaVerifyFailed( ERR_get_error() );
	
	return epp2.msg.relinquish();
}

Allocated decryptVerify1( Keys *privDecSign, const String &msg )
{
	PacketSignedEncrypted epp1( msg );

	/* Decrypt the key. */
	String sessionKey( RSA_size( privDecSign->rsa ) );
	long skLen = RSA_private_decrypt( epp1.protKey.length, epp1.protKey.binary(),
			sessionKey.binary(), privDecSign->rsa, RSA_PKCS1_PADDING );
	if ( skLen < 0 )
		throw RsaPrivateDecryptFailed( ERR_get_error() );

	String dec( epp1.enc.length );
	RC4_KEY rc4Key;
	RC4_set_key( &rc4Key, skLen, sessionKey.binary() );
	RC4( &rc4Key, epp1.enc.length, epp1.enc.binary(), dec.binary() );

	return dec.relinquish();
}

Allocated decryptVerify2( Keys *pubEncVer, Keys *privDecSign, const String &dec )
{
	PacketSignedId signedId( dec );

	String nBin = bnToBin( privDecSign->rsa->n );
	String eBin = bnToBin( privDecSign->rsa->e );
	String verifyData = concatenate( 3, &nBin, &eBin, &signedId.msg );

	/* Verify the item. */
	u_char decryptedSha1[SHA_DIGEST_LENGTH];
	SHA1( verifyData.binary(), verifyData.length, decryptedSha1 );
	int verifyres = RSA_verify( NID_sha1, decryptedSha1, SHA_DIGEST_LENGTH, 
			signedId.sig.binary(), signedId.sig.length, pubEncVer->rsa );
	if ( verifyres != 1 )
		throw RsaVerifyFailed( ERR_get_error() );
	
	return signedId.msg.relinquish();
}


Allocated bkEncrypt( const String &bk, const String &msg )
{
	/* Convert the broadcst_key to binary. */
	String broadcastKey = base64ToBin( bk );

	/* Encrypt the message using the session key. */
	String encrypted( msg.length );
	RC4_KEY rc4Key;
	RC4_set_key( &rc4Key, SK_SIZE, broadcastKey.binary() );
	RC4( &rc4Key, msg.length, msg.binary(), encrypted.binary() );

	return consBkEncrypted( encrypted );
}
	
Allocated bkDecrypt( const String &bk, const String &msg )
{
	PacketBkEncrypted epp1( msg );

	/* Convert the broadcst_key to binary. */
	String broadcastKey = base64ToBin( bk );

	/* Decrypt. */
	String dec( epp1.enc.length );
	RC4_KEY rc4Key;
	RC4_set_key( &rc4Key, broadcastKey.length, broadcastKey.binary() );
	RC4( &rc4Key, epp1.enc.length, epp1.enc.binary(), dec.binary() );

	return dec.relinquish();
}

Allocated bkSignEncrypt( Keys *privDecSign, const String &bk, const String &msg )
{
	/* Convert the broadcst_key to binary. */
	String broadcastKey = base64ToBin( bk );

	/* Need to make a buffer containing both the broadcast key and message so
	 * we can sign both. */
	String signData = concatenate( 2, &broadcastKey, &msg );

	/* Sign the message. */
	u_char msgSha1[SHA_DIGEST_LENGTH];
	SHA1( signData.binary(), signData.length, msgSha1 );

	String sigBin( RSA_size(privDecSign->rsa) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, msgSha1, SHA_DIGEST_LENGTH, 
			sigBin.binary(), &sigLen, privDecSign->rsa );

	if ( signRes != 1 )
		throw RsaSignFailed( ERR_get_error() ) ;
	
	/* Make a single buffer containing the plain data. */
	String plainData = consSigned( sigBin, msg );

	/* Encrypt the message using the session key. */
	String encrypted( plainData.length );
	RC4_KEY rc4Key;
	RC4_set_key( &rc4Key, SK_SIZE, broadcastKey.binary() );
	RC4( &rc4Key, plainData.length, plainData.binary(), encrypted.binary() );

	return consBkSignedEncrypted( encrypted );
}
	
Allocated bkDecryptVerify( Keys *pubEncVer, const String &bk, const String &msg )
{
	PacketBkSignedEncrypted epp1( msg );

	/* Convert the broadcst_key to binary. */
	String broadcastKey = base64ToBin( bk );

	/* Decrypt. */
	String dec( epp1.enc.length );
	RC4_KEY rc4Key;
	RC4_set_key( &rc4Key, broadcastKey.length, broadcastKey.binary() );
	RC4( &rc4Key, epp1.enc.length, epp1.enc.binary(), dec.binary() );

	PacketSigned epp2( dec );

	/* Need to make a buffer containing both the session key an message so we
	 * can verify the message was originally signed with this key. */
	String verifyData = concatenate( 2, &broadcastKey, &epp2.msg );

	/* Verify the message. */
	u_char decryptedSha1[SHA_DIGEST_LENGTH];
	SHA1( verifyData.binary(), verifyData.length, decryptedSha1 );
	int verifyres = RSA_verify( NID_sha1, decryptedSha1,
			SHA_DIGEST_LENGTH, epp2.sig.binary(), epp2.sig.length, pubEncVer->rsa );
	if ( verifyres != 1 )
		throw RsaVerifyFailed( ERR_get_error() );
	
	return epp2.msg.relinquish();
}


Allocated bkSign( Keys *privDecSign, const String &bk, const String &msg )
{
	/* Convert the broadcst_key to binary. */
	String broadcastKey = base64ToBin( bk );

	/* Need to make a buffer containing both the broadcast key and message so
	 * we can sign both. */
	String signData = concatenate( 2, &broadcastKey, &msg );

	/* Sign the message. */
	u_char msgSha1[SHA_DIGEST_LENGTH];
	SHA1( signData.binary(), signData.length, msgSha1 );

	String sigBin( RSA_size(privDecSign->rsa) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, msgSha1, SHA_DIGEST_LENGTH, 
			sigBin.binary(), &sigLen, privDecSign->rsa );

	if ( signRes != 1 )
		throw RsaSignFailed( ERR_get_error() ) ;
	
	/* Make a single buffer containing the plain data. */
	return consSigned( sigBin, msg );
}

Allocated bkVerify( Keys *pubEncVer, const String &bk, const String &msg )
{
	/* Convert the broadcst_key to binary. */
	String broadcastKey = base64ToBin( bk );

	PacketSigned epp( msg );

	/* Need to make a buffer containing both the session key an message so we
	 * can verify the message was originally signed with this key. */
	String verifyData = concatenate( 2, &broadcastKey, &epp.msg );

	/* Verify the message. */
	u_char decryptedSha1[SHA_DIGEST_LENGTH];
	SHA1( verifyData.binary(), verifyData.length, decryptedSha1 );
	int verifyres = RSA_verify( NID_sha1, decryptedSha1,
			SHA_DIGEST_LENGTH, epp.sig.binary(), epp.sig.length, pubEncVer->rsa );
	if ( verifyres != 1 )
		throw RsaVerifyFailed( ERR_get_error() );
	
	return epp.msg.relinquish();
}

Allocated bkDetachedSign( Keys *privDecSign, const String &bk, const String &msg )
{
	/* Convert the broadcst_key to binary. */
	String broadcastKey = base64ToBin( bk );

	/* Need to make a buffer containing both the broadcast key and message so
	 * we can sign both. */
	String signData = concatenate( 2, &broadcastKey, &msg );

	/* Sign the message. */
	u_char msgSha1[SHA_DIGEST_LENGTH];
	SHA1( signData.binary(), signData.length, msgSha1 );

	String sigBin( RSA_size(privDecSign->rsa) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, msgSha1, SHA_DIGEST_LENGTH, 
			sigBin.binary(), &sigLen, privDecSign->rsa );

	if ( signRes != 1 )
		throw RsaSignFailed( ERR_get_error() ) ;
	
	/* Make a single buffer containing the plain data. */
	return consDetachedSig( sigBin );
}

bool bkDetachedVerify( Keys *pubEncVer, const String &bk, const String &sig, const String &plainMsg )
{
	PacketDetachedSig epp( sig );

	/* Convert the broadcst_key to binary. */
	String broadcastKey = base64ToBin( bk );

	/* Need to make a buffer containing both the session key an message so we
	 * can verify the message was originally signed with this key. */
	String verifyData = concatenate( 2, &broadcastKey, &plainMsg );

	/* Verify the message. */
	u_char decryptedSha1[SHA_DIGEST_LENGTH];
	SHA1( verifyData.binary(), verifyData.length, decryptedSha1 );
	int verifyres = RSA_verify( NID_sha1, decryptedSha1,
			SHA_DIGEST_LENGTH, epp.sig.binary(), epp.sig.length, pubEncVer->rsa );
	if ( verifyres != 1 )
		throw RsaVerifyFailed( ERR_get_error() );
	
	return true;
}

Allocated pwEncrypt( const String &pass, const String &msg )
{
	u_char pwSha1[SHA_DIGEST_LENGTH];
	SHA1( pass.binary(), pass.length, pwSha1 );

	String encryptedBin( msg.length );

	RC4_KEY rc4Key;
	RC4_set_key( &rc4Key, SHA_DIGEST_LENGTH, pwSha1 );
	RC4( &rc4Key, msg.length, msg.binary(), encryptedBin.binary() );

	return consPwEncrypted( encryptedBin );
}

Allocated pwDecrypt( const String &pass, const String &msg )
{
	PacketPwEncrypted epp( msg );

	u_char pwSha1[SHA_DIGEST_LENGTH];
	SHA1( pass.binary(), pass.length, pwSha1 );

	String plain( epp.enc.length );

	RC4_KEY rc4Key;
	RC4_set_key( &rc4Key, SHA_DIGEST_LENGTH, pwSha1 );
	RC4( &rc4Key, epp.enc.length, epp.enc.binary(), plain.binary() );

	return plain.relinquish();
}

Allocated sign( Keys *privSign, const String &msg )
{
	/* Sign the message. */
	u_char msgSha1[SHA_DIGEST_LENGTH];
	SHA1( msg.binary(), msg.length, msgSha1 );

	String sigBin( RSA_size(privSign->rsa) );
	unsigned sigLen;
	int signRes = RSA_sign( NID_sha1, msgSha1, SHA_DIGEST_LENGTH, 
			sigBin.binary(), &sigLen, privSign->rsa );

	if ( signRes != 1 )
		throw RsaSignFailed( ERR_get_error() );
	
	/* Result. */
	return consSigned( sigBin, msg );
}

Allocated verify( Keys *pubVer, const String &msg )
{
	PacketSigned epp( msg );

	/* Verify the item. */
	u_char msgSha1[SHA_DIGEST_LENGTH];
	SHA1( epp.msg.binary(), epp.msg.length, msgSha1 );
	int verifyres = RSA_verify( NID_sha1, msgSha1, SHA_DIGEST_LENGTH, 
			epp.sig.binary(), epp.sig.length, pubVer->rsa );
	if ( verifyres != 1 )
		throw RsaVerifyFailed( ERR_get_error() );

	return epp.msg.relinquish();
}
