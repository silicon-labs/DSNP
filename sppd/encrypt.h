/*
 * Copyright (c) 2009-2009, Adrian Thurston <thurston@complang.org>
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

#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rc4.h>
#include <sys/types.h>

struct Encrypt
{
	Encrypt()
	:
		pubEncVer(0), privDecSign(0), 
		enc(0), sig(0)
	{}

	~Encrypt()
	{
		clear();
	}

	void load( RSA *pubEncVer, RSA *privDecSign )
	{
		this->pubEncVer = pubEncVer;
		this->privDecSign = privDecSign;
	}

	int sign( u_char *src, long len );
	int verify( u_char *msg, long len, const char *srcSig );

	int encryptSign( u_char *src, long len );
	int decryptVerify( const char *enc, const char *sig );

	int symEncryptSign( u_char *src, long len );
	int symDecryptVerify( const char *enc, const char *sig, const char *message );

	int skEncryptSign( const char *sk, u_char *src, long len );
	int skDecryptVerify( const char *sk, const char *sig, const char *message );

	void clear()
	{
		if ( enc != 0 )
			delete[] enc;
		if ( sig != 0 )
			delete[] sig;
		enc = 0;
		sig = 0;
	}

	RSA *pubEncVer;
	RSA *privDecSign;

	/* For encryption. */
	char *enc;
	char *sig;
	char *sym;

	u_char *session_key;
	long skLen;

	/* For decryption. */
	u_char *decrypted;
	long decLen;

	char err[120];
};

#endif
