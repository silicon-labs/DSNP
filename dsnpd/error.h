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

#define EC_SSL_PEER_FAILED_VERIFY       100
#define EC_FRIEND_REQUEST_EXISTS        101
#define EC_DSNPD_NO_RESPONSE            102
#define EC_DSNPD_TIMEOUT                103
#define EC_SOCKET_CONNECT_FAILED        104
#define EC_SSL_CONNECT_FAILED           105
#define EC_SSL_WRONG_HOST               106
#define EC_SSL_CA_CERT_LOAD_FAILURE     107
#define EC_FRIEND_CLAIM_EXISTS          108
#define EC_CANNOT_FRIEND_SELF           109
#define EC_USER_NOT_FOUND               110
#define EC_INVALID_ROUTE                111
#define EC_USER_EXISTS                  112
#define EC_RSA_KEY_GEN_FAILED           113
#define EC_INVALID_LOGIN                114
#define EC_DATABASE_ERROR               115
#define EC_INVALID_USER                 116
#define EC_READ_ERROR                   117
#define EC_PARSE_ERROR                  118
#define EC_RESPONSE_IS_ERROR            119
#define EC_SSL_NEW_CONTEXT_FAILURE      120
#define EC_SSL_CA_CERTS_NOT_SET         121
#define EC_FRIEND_REQUEST_INVALID       122
#define EC_IDENTITY_ID_INVALID          123
#define EC_USER_ID_INVALID              124
#define EC_STOPPING                     125
#define EC_NOT_PREFRIEND                126
#define EC_DECRYPT_VERIFY_FAILED        127         
#define EC_NO_PRIMARY_NETWORK           128
#define EC_FRIEND_CLAIM_NOT_FOUND       129
#define EC_PUT_KEY_FETCH_ERROR          130
#define EC_INVALID_RELID                131
#define EC_IDENTITY_HASH_INVALID        132
#define EC_INVALID_FTOKEN               133
#define EC_INVALID_FTOKEN_REQUEST       134
#define EC_FLOGIN_TOKEN_WRONG_SIZE      135
#define EC_BROADCAST_RECIPIENT_INVALID  136
#define EC_REQUEST_ID_INVALID           137
#define EC_LOGIN_TOKEN_INVALID          138
#define EC_TOKEN_WRONG_SIZE             139
#define EC_NOT_IMPLEMENTED              140

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

struct FriendRequestInvalid
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_FRIEND_REQUEST_INVALID );

		error( "%d friend request is not valid\n",
				EC_FRIEND_REQUEST_INVALID );
	}
};

struct FriendClaimNotFound
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_FRIEND_CLAIM_NOT_FOUND );

		error( "%d expected friend claim was not found\n",
				EC_FRIEND_CLAIM_NOT_FOUND );
	}
};

struct InvalidRelid
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_INVALID_RELID );

		error( "%d relid supplied does not identify a friend claim\n",
				EC_INVALID_RELID );
	}
};

struct IdentityIdInvalid
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_IDENTITY_ID_INVALID );

		error( "%d identity id supplied is not valid\n",
				EC_IDENTITY_ID_INVALID );
	}
};

struct UserIdInvalid
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_USER_ID_INVALID );

		error( "%d user id supplied is not valid\n",
				EC_USER_ID_INVALID );
	}
};

struct Stopping
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_STOPPING );

		error( "%d stopping\n",
				EC_STOPPING );
	}
};

struct NotPrefriend
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_NOT_PREFRIEND );

		error( "%d not a prefriend\n",
				EC_NOT_PREFRIEND );
	}
};

struct DecryptVerifyFailed
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_DECRYPT_VERIFY_FAILED );

		error( "%d decrypt verify failed\n",
				EC_DECRYPT_VERIFY_FAILED );
	}
};


struct NoPrimaryNetwork
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_NO_PRIMARY_NETWORK );

		error( "%d primary network not found\n",
				EC_NO_PRIMARY_NETWORK );
	}

};

struct PutKeyFetchError
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_PUT_KEY_FETCH_ERROR );

		error( "%d error fetching current put key\n",
				EC_PUT_KEY_FETCH_ERROR );
	}

};

struct IdentityHashInvalid
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_IDENTITY_HASH_INVALID );

		error( "%d identity hash not valid\n",
				EC_IDENTITY_HASH_INVALID );
	}

};

struct FtokenInvalid
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_INVALID_FTOKEN );

		error( "%d supplied ftoken is not valid\n",
				EC_INVALID_FTOKEN );
	}

};

struct FtokenRequestInvalid
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_INVALID_FTOKEN_REQUEST );

		error( "%d supplied ftoken is not valid\n",
				EC_INVALID_FTOKEN_REQUEST );
	}

};

struct FloginTokenWrongSize
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_FLOGIN_TOKEN_WRONG_SIZE );

		error( "%d flogin token is the wrong size\n",
				EC_FLOGIN_TOKEN_WRONG_SIZE );
	}

};

struct TokenWrongSize
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_TOKEN_WRONG_SIZE );

		error( "%d flogin token is the wrong size\n",
				EC_TOKEN_WRONG_SIZE );
	}

};

struct BroadcastRecipientInvalid
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_BROADCAST_RECIPIENT_INVALID );

		error( "%d broadcast recpient invalid\n",
				EC_BROADCAST_RECIPIENT_INVALID );
	}
};

struct RequestIdInvalid
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_REQUEST_ID_INVALID );

		error( "%d request id invalid\n",
				EC_REQUEST_ID_INVALID );
	}
};

struct LoginTokenNotValid
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_LOGIN_TOKEN_INVALID );

		error( "%d login token not valid\n",
				EC_LOGIN_TOKEN_INVALID );
	}
};

struct NotImplemented
	: public UserError
{
	virtual void print( BIO *bio )
	{
		BIO_printf( bio,
				"ERROR %d\r\n",
				EC_NOT_IMPLEMENTED );

		error( "%d function not implemented\n",
				EC_NOT_IMPLEMENTED );
	}
};

#endif
