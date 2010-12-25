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

#define EC_SSL_PEER_FAILED_VERIFY 100
#define EC_FRIEND_REQUEST_EXISTS  101
#define EC_DSNPD_NO_RESPONSE      102
#define EC_DSNPD_TIMEOUT          103
#define EC_SOCKET_CONNECT_FAILED  104
#define EC_SSL_CONNECT_FAILED     105
#define EC_SSL_WRONG_HOST         106

struct UserError
{
	virtual void print( BIO *bio ) = 0;
};

struct SslPeerFailedVerify
	: public UserError
{
	SslPeerFailedVerify( const char *host )
		: host( host )
	{}

	String host;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s\r\n",
				EC_SSL_PEER_FAILED_VERIFY,
				host.data );

		error( "%d peer %s failed SSL verification\r\n",
				EC_SSL_PEER_FAILED_VERIFY,
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

struct SocketConnectFailed
	: public UserError
{
	SocketConnectFailed( const char *host )
		: host( host )
	{}

	String host;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s\r\n",
				EC_SOCKET_CONNECT_FAILED,
				host.data );

		error( "%d could not connect to %s\n",
				EC_SOCKET_CONNECT_FAILED,
				host.data );
	}
};


struct SslConnectFailed
	: public UserError
{
	SslConnectFailed( const char *host )
		: host( host )
	{}

	String host;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s\r\n",
				EC_SSL_CONNECT_FAILED,
				host.data );

		error( "%d SSL_connect to %s failed\r\n",
				EC_SSL_CONNECT_FAILED,
				host.data );
	}
};

struct SslPeerCnHostMismatch
	: public UserError
{
	SslPeerCnHostMismatch( const char *expected, const char *got )
		: expected(expected), got(got)
	{}

	String expected;
	String got;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s %s\r\n",
				EC_SSL_WRONG_HOST,
				expected.data, got.data );

		error( "%d verified SSL connection to %s, but cert presented belongs to %s\r\n",
				EC_SSL_WRONG_HOST,
				expected.data, got.data );
	}
};


#endif

