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

#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include "string.h"
#include "parser.h"
#include "buffer.h"
#include "dlist.h"
#include "recipients.h"

#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rc4.h>
#include <sys/types.h>
#include <list>
#include <string>

struct Keys;

struct PrivateKey
{
	String n;
	String e;
	String d;
	String p;
	String q;
	String dmp1;
	String dmq1;
	String iqmp;
};

struct BroadcastSubject
{
	String subject;
	String subjectSig;
	String subjectRelid;

	BroadcastSubject *prev, *next;
};

typedef DList<BroadcastSubject> BroadcastSubjectList;

struct Broadcast
{
	/* Publisher's broadcast key. */
	long long bkId;
	String distName;
	long long generation;

	String user;
	String author;
	String publisher;

	String authorSig;
	String publisherSig;

	String authorRelid;
	String publisherRelid;

	BroadcastSubjectList subjectList;

	String plainMsg;
};


Allocated signEncrypt( Keys *pubEncVer, Keys *privDecSign, const String *iduri, const String &msg );
Allocated decryptVerify( Keys *pubEncVer, Keys *privDecSign, const String &msg );
Allocated decryptVerify1( Keys *privDecSign, const String &msg );
Allocated decryptVerify2( Keys *pubEncVer, Keys *privDecSign, const String &msg );

Allocated bkEncrypt( const String &bk, const String &msg );
Allocated bkDecrypt( const String &bk, const String &msg );

Allocated bkSignEncrypt( Keys *privDecSign, const String &bk, const String &msg );
Allocated bkDecryptVerify( Keys *pubEncVer, const String &bk, const String &msg );

Allocated bkSign( Keys *privDecSign, const String &bk, const String &msg );
Allocated bkVerify( Keys *pubEncVer, const String &bk, const String &msg );

Allocated bkDetachedSign( Keys *privDecSign, const String &bk, const String &msg );
bool bkDetachedVerify( Keys *pubEncVer, const String &bk,
		const String &sigMsg, const String &plainMsg );

Allocated pwEncrypt( const String &pass, const String &msg );
Allocated pwDecrypt( const String &pass, const String &msg );

Allocated sign( Keys *privSign, const String &msg );
Allocated verify( Keys *pubVer, const String &msg );

struct RelidSet
{
	String priv0;
	String priv1;
	String priv2;
	String priv3;
	String priv4;

	void generate();
};


#endif
