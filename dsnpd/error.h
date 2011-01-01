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

#define EC_SSL_PEER_FAILED_VERIFY    100
#define EC_FRIEND_REQUEST_EXISTS     101
#define EC_DSNPD_NO_RESPONSE         102
#define EC_DSNPD_TIMEOUT             103
#define EC_SOCKET_CONNECT_FAILED     104
#define EC_SSL_CONNECT_FAILED        105
#define EC_SSL_WRONG_HOST            106
#define EC_SSL_CA_CERT_LOAD_FAILURE  107
#define EC_FRIEND_CLAIM_EXISTS       108
#define EC_CANNOT_FRIEND_SELF        109
#define EC_USER_NOT_FOUND            110
#define EC_INVALID_ROUTE             111
#define EC_USER_EXISTS               112
#define EC_RSA_KEY_GEN_FAILED        113
#define EC_INVALID_LOGIN             114
#define EC_DATABASE_ERROR            115
#define EC_INVALID_USER              116
#define EC_READ_ERROR                117
#define EC_PARSE_ERROR               118
#define EC_RESPONSE_IS_ERROR         119
#define EC_SSL_NEW_CONTEXT_FAILURE   120
#define EC_SSL_CA_CERTS_NOT_SET      121

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

		error( "%d peer %s failed SSL verification\n",
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

		error( "%d friend request from %s for %s already exists\n",
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

		error( "%d SSL_connect to %s failed\n",
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

		error( "%d verified SSL connection to %s, but cert presented belongs to %s\n",
				EC_SSL_WRONG_HOST,
				expected.data, got.data );
	}
};

struct SslCaCertLoadFailure
	: public UserError
{
	SslCaCertLoadFailure( const char *file )
		: file( file )
	{}

	String file;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s\r\n",
				EC_SSL_CA_CERT_LOAD_FAILURE,
				file.data );

		error( "%d failed to load CA cert file %s\n",
				EC_SSL_CA_CERT_LOAD_FAILURE,
				file.data );
	}
};

struct FriendClaimExists
	: public UserError
{
	FriendClaimExists( const char *user, const char *identity )
		: user(user), identity(identity) {}

	String user;
	String identity;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s %s\r\n",
				EC_FRIEND_CLAIM_EXISTS,
				user.data, identity.data );

		error( "%d user %s is already friends with identity %s\n",
				EC_FRIEND_CLAIM_EXISTS,
				user.data, identity.data );
	}
};

struct CannotFriendSelf
	: public UserError
{
	CannotFriendSelf( const char *identity )
		: identity(identity) {}

	String identity;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s\r\n",
				EC_CANNOT_FRIEND_SELF,
				identity.data );

		error( "%d cannot friend oneself %s\n",
				EC_CANNOT_FRIEND_SELF,
				identity.data );
	}
};

struct UserExists
	: public UserError
{
	UserExists( const char *user )
		: user(user) {}

	String user;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s\r\n",
				EC_USER_EXISTS,
				user.data );

		error( "%d user %s already exists\n",
				EC_USER_EXISTS,
				user.data );
	}
};

struct RsaKeyGenError
	: public UserError
{
	RsaKeyGenError( unsigned long code )
		: code(code) {}

	unsigned long code;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d\r\n",
				EC_RSA_KEY_GEN_FAILED );

		error( "%d RSA key generation failed\n",
				EC_RSA_KEY_GEN_FAILED );
	}
};

struct InvalidLogin
	: public UserError
{
	InvalidLogin( const char *user, const char *pass, const char *reason )
		: user(user), pass(pass), reason(reason) {}

	String user, pass, reason;
	
	virtual void print( BIO *bio )
	{
		/* Don't give the reason to the UI. */
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_INVALID_LOGIN );

		error( "%d invalid login for user %s due to %s\n", 
				EC_RSA_KEY_GEN_FAILED, user.data, reason.data );
	}
};

struct InvalidUser
	: public UserError
{
	InvalidUser( const char *user )
		: user(user) {}

	String user;

	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d %s\r\n",
				EC_INVALID_USER,
				user.data );

		error( "%d user %s does not exist\n",
				EC_INVALID_USER,
				user.data );
	}
};

struct ReadError
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d\r\n",
				EC_READ_ERROR );

		error( "%d communication error: read error\n",
				EC_READ_ERROR );
	}
};

struct ParseError
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d\r\n",
				EC_PARSE_ERROR );

		error( "%d communication error: parse error\n",
				EC_PARSE_ERROR );
	}
};

struct ResponseIsError
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d\r\n",
				EC_RESPONSE_IS_ERROR );

		error( "%d communication error: server returned failure code\n",
				EC_RESPONSE_IS_ERROR );
	}
};

struct SslNewContextFailure
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d\r\n",
				EC_SSL_NEW_CONTEXT_FAILURE );

		error( "%d SSL error: new context failure\n",
				EC_SSL_NEW_CONTEXT_FAILURE );
	}
};

struct SslCaCertsNotSet
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio, 
				"ERROR %d\r\n",
				EC_SSL_CA_CERTS_NOT_SET );

		error( "%d SSL error: CA_CERTS is not set\n",
				EC_SSL_CA_CERTS_NOT_SET );
	}
};

#endif
