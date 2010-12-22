/*
 * Copyright (c) 2010, Adrian Thurston <thurston@complang.org>
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

#ifndef _USERERR_H
#define _USERERR_H

#include "string.h"

#include <openssl/bio.h>

#define EC_PEER_FAILED_SSL 100
#define EC_FRIEND_REQUEST_EXISTS 101

struct UserError
{
	virtual void print( BIO *bio ) = 0;
};

struct PeerFailedSsl
	: public UserError
{
	PeerFailedSsl( const char *host )
		: host( host )
	{}

	String host;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s\r\n",
				EC_PEER_FAILED_SSL,
				host.data );

		error( "%d peer %s failed SSL verification\r\n",
				EC_PEER_FAILED_SSL,
				host.data );
	}
};

struct FriendRequestExists
	: public UserError
{
	FriendRequestExists( const char *user, const char *identity )
		: user(user), identity(identity)
	{}

	String user;
	String identity;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s %s\r\n",
				EC_FRIEND_REQUEST_EXISTS,
				user.data, identity.data );

		error( "%d friend request from %s for %s already exists\r\n",
				EC_FRIEND_REQUEST_EXISTS,
				user.data, identity.data );
	}
};

#endif

