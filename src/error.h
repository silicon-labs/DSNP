/*
 * Copyright (c) 2010-2011, Adrian Thurston <thurston@complang.org>
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
#include "errno.h"

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
#define EC_RSA_SIGN_FAILED              127         
#define EC_NO_PRIMARY_NETWORK           128
#define EC_FRIEND_CLAIM_NOT_FOUND       129
#define EC_PUT_KEY_FETCH_ERROR          130
#define EC_INVALID_RELID                131
#define EC_IDENTITY_HASH_INVALID        132
#define EC_INVALID_FLOGIN_TOKEN         133
#define EC_INVALID_FTOKEN_REQUEST       134
#define EC_FLOGIN_TOKEN_WRONG_SIZE      135
#define EC_BROADCAST_RECIPIENT_INVALID  136
#define EC_REQUEST_ID_INVALID           137
#define EC_LOGIN_TOKEN_INVALID          138
#define EC_TOKEN_WRONG_SIZE             139
#define EC_NOT_IMPLEMENTED              140
#define EC_MISSING_KEYS                 141
#define EC_VERSION_ALREADY_GIVEN        142
#define EC_DATABASE_CONNECTION_FAILED   143
#define EC_NO_COMMON_VERSION            144
#define EC_INVALID_COMM_KEY             145
#define EC_BAD_SITE                     146
#define EC_EXPECTED_TLS                 147
#define EC_EXPECTED_LOCAL_KEY           148
#define EC_BASE64_PARSE_ERROR           149
#define EC_INVALID_USER_NAME            150
#define EC_PARSE_BUFFER_EXHAUSTED       151
#define EC_SSL_ACCEPT_FAILED            152
#define EC_NONBLOCKING_IO_NOT_AVAILABLE 153
#define EC_FCNTL_QUERY_FAILED           154
#define EC_WRITE_ERROR                  155
#define EC_DAEMON_DAEMON_TIMEOUT        156
#define EC_LOG_FILE_OPEN_FAILED         157
#define EC_CONF_FILE_OPEN_FAILED        158
#define EC_SSL_FAILED_TO_LOAD           159
#define EC_SSL_PARAM_NOT_SET            160
#define EC_SSL_CONTEXT_CREATION_FAILED  161
#define EC_DSNPD_DB_QUERY_FAILED        162
#define EC_SCHEMA_VERSION_MISMATCH      163
#define EC_MUST_LOGIN                   164
#define EC_RSA_PUBLIC_ENCRYPT_FAILED    165
#define EC_RSA_PRIVATE_DECRYPT_FAILED   166
#define EC_RSA_VERIFY_FAILED            167
#define EC_INVALID_LOGIN_TOKEN          168
#define EC_SOCKADDR_ERROR               169
#define EC_SOCK_NOT_LOCAL               170
#define EC_CONF_PARSE_ERROR             171
#define EC_UNEXPECTED_FC_STATE          172
#define EC_INVALID_REMOTE_BR_REQ        173
#define EC_INVALID_REMOTE_BR_RSP        174
#define EC_INVALID_REMOTE_BR_SUBJ       175
#define EC_BAD_HOST                     176
#define EC_WRITE_ON_NULL_SOCKET_BIO     177
#define EC_WRONG_NUMBER_OF_RELIDS       178

struct UserError
{
	virtual void print( BioWrap &bio ) = 0;
};

struct SslPeerFailedVerify
	: public UserError
{
	SslPeerFailedVerify( const char *host )
		: host( Pointer(host) )
	{}

	String host;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SSL_PEER_FAILED_VERIFY, host.data );

		error( "%d peer %s failed SSL verification\n",
				EC_SSL_PEER_FAILED_VERIFY,
				host.data );
	}
};

struct FriendRequestExists
	: public UserError
{
	FriendRequestExists( const char *user, const char *identity )
		: user(Pointer(user)), identity(Pointer(identity))
	{}

	String user;
	String identity;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_FRIEND_REQUEST_EXISTS, user.data, identity.data );

		error( "%d friend request from %s for %s already exists\n",
				EC_FRIEND_REQUEST_EXISTS,
				user.data, identity.data );
	}
};

struct SocketConnectFailed
	: public UserError
{
	SocketConnectFailed( const char *host )
		: host( Pointer(host) )
	{}

	String host;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SOCKET_CONNECT_FAILED, host.data );

		error( "%d could not connect to %s\n",
				EC_SOCKET_CONNECT_FAILED,
				host.data );
	}
};


struct NonBlockingIoNotAvailable
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_NONBLOCKING_IO_NOT_AVAILABLE );

		error( "%d non-blocking IO is not available\n",
				EC_NONBLOCKING_IO_NOT_AVAILABLE );
	}
};

struct FnctlQueryFailed
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_FCNTL_QUERY_FAILED );

		error( "%d could not query flags on FD\n",
				EC_FCNTL_QUERY_FAILED );
	}
};


struct SslConnectFailed
	: public UserError
{
	SslConnectFailed() {}

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SSL_CONNECT_FAILED );

		error( "%d SSL_connect failed\n",
				EC_SSL_CONNECT_FAILED );
	}
};

struct SslAcceptFailed
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SSL_ACCEPT_FAILED );

		error( "%d SSL_accept failed\n",
				EC_SSL_ACCEPT_FAILED );
	}
};

struct SslPeerCnHostMismatch
	: public UserError
{
	SslPeerCnHostMismatch( const char *expected, const char *got )
		: expected(Pointer(expected)), got(Pointer(got))
	{}

	String expected;
	String got;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SSL_WRONG_HOST, expected.data, got.data );

		error( "%d verified SSL connection to %s, but cert presented belongs to %s\n",
				EC_SSL_WRONG_HOST,
				expected.data, got.data );
	}
};

struct SslCaCertLoadFailure
	: public UserError
{
	SslCaCertLoadFailure( const char *file )
		: file( Pointer(file) )
	{}

	String file;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SSL_CA_CERT_LOAD_FAILURE, file.data );

		error( "%d failed to load CA cert file %s\n",
				EC_SSL_CA_CERT_LOAD_FAILURE,
				file.data );
	}
};

struct FriendClaimExists
	: public UserError
{
	FriendClaimExists( const char *user, const char *identity )
		: user(Pointer(user)), identity(Pointer(identity)) {}

	String user;
	String identity;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_FRIEND_CLAIM_EXISTS, user.data, identity.data );

		error( "%d user %s is already friends with identity %s\n",
				EC_FRIEND_CLAIM_EXISTS,
				user.data, identity.data );
	}
};

struct CannotFriendSelf
	: public UserError
{
	CannotFriendSelf( const char *identity )
		: identity(Pointer(identity)) {}

	String identity;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_CANNOT_FRIEND_SELF, identity.data );

		error( "%d cannot friend oneself %s\n",
				EC_CANNOT_FRIEND_SELF,
				identity.data );
	}
};

struct UserExists
	: public UserError
{
	UserExists( const char *user )
		: user(Pointer(user)) {}

	String user;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_USER_EXISTS, user.data );

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

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_RSA_KEY_GEN_FAILED );

		error( "%d RSA key generation failed\n",
				EC_RSA_KEY_GEN_FAILED );
	}
};

struct InvalidLogin
	: public UserError
{
	InvalidLogin( const char *user, const char *pass, const char *reason )
		: user(Pointer(user)), pass(Pointer(pass)), reason(Pointer(reason)) {}

	String user, pass, reason;
	
	virtual void print( BioWrap &bio )
	{
		/* Don't give the reason to the UI. */
		bio.returnError( EC_INVALID_LOGIN );

		error( "%d invalid login for user %s due to %s\n", 
				EC_RSA_KEY_GEN_FAILED, user.data, reason.data );
	}
};

struct InvalidUser
	: public UserError
{
	InvalidUser( const char *user )
		: user(Pointer(user)) {}

	String user;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_INVALID_USER, user.data );

		error( "%d user %s does not exist\n",
				EC_INVALID_USER,
				user.data );
	}
};

struct ReadError
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_READ_ERROR );

		error( "%d communication error: read error\n",
				EC_READ_ERROR );
	}
};

struct ParseError
	: public UserError
{
	ParseError( const char *src, int line )
		: src(Pointer(src)), line(line) {}

	String src;
	int line;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_PARSE_ERROR );

		if ( src.length != 0 ) {
			error( "%d communication error: parse error: %s line %d\n",
					EC_PARSE_ERROR, src(), line );
		}
		else {
			error( "%d communication error: parse error\n",
					EC_PARSE_ERROR );
		}
	}
};

struct ResponseIsError
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_RESPONSE_IS_ERROR );

		error( "%d communication error: server returned failure code\n",
				EC_RESPONSE_IS_ERROR );
	}
};

struct SslNewContextFailure
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SSL_NEW_CONTEXT_FAILURE );

		error( "%d SSL error: new context failure\n",
				EC_SSL_NEW_CONTEXT_FAILURE );
	}
};

struct SslCaCertsNotSet
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SSL_CA_CERTS_NOT_SET );

		error( "%d SSL error: CA_CERTS is not set\n",
				EC_SSL_CA_CERTS_NOT_SET );
	}
};

struct FriendRequestInvalid
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_FRIEND_REQUEST_INVALID );

		error( "%d friend request is not valid\n",
				EC_FRIEND_REQUEST_INVALID );
	}
};

struct UnexpectedFriendClaimState
	: public UserError
{
	UnexpectedFriendClaimState( int state )
		: state(state) {}
	
	int state;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_UNEXPECTED_FC_STATE );

		error( "%d friend claim in unexpected state %d\n",
				EC_UNEXPECTED_FC_STATE, state );
	}
};


struct FriendClaimNotFound
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_FRIEND_CLAIM_NOT_FOUND );

		error( "%d expected friend claim was not found\n",
				EC_FRIEND_CLAIM_NOT_FOUND );
	}
};

struct InvalidRelid
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_INVALID_RELID );

		error( "%d relid supplied does not identify a friend claim\n",
				EC_INVALID_RELID );
	}
};

struct IdentityIdInvalid
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_IDENTITY_ID_INVALID );

		error( "%d identity id supplied is not valid\n",
				EC_IDENTITY_ID_INVALID );
	}
};

struct UserIdInvalid
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_USER_ID_INVALID );

		error( "%d user id supplied is not valid\n",
				EC_USER_ID_INVALID );
	}
};

struct Stopping
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_STOPPING );

		error( "%d stopping\n",
				EC_STOPPING );
	}
};

struct NotPrefriend
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_NOT_PREFRIEND );

		error( "%d not a prefriend\n",
				EC_NOT_PREFRIEND );
	}
};

struct RsaSignFailed
	: public UserError
{
	RsaSignFailed( long errorCode )
		: errorCode(errorCode) {}

	long errorCode;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_RSA_SIGN_FAILED );

		error( "%d RSA_sign failed\n",
				EC_RSA_SIGN_FAILED );
	}
};

struct RsaPublicEncryptFailed
	: public UserError
{
	RsaPublicEncryptFailed( long errorCode )
		: errorCode(errorCode) {}

	long errorCode;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_RSA_PUBLIC_ENCRYPT_FAILED );

		error( "%d RSA_public_encrypt failed\n",
				EC_RSA_PUBLIC_ENCRYPT_FAILED );
	}
};

struct RsaPrivateDecryptFailed
	: public UserError
{
	RsaPrivateDecryptFailed( long errorCode )
		: errorCode(errorCode) {}

	long errorCode;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_RSA_PRIVATE_DECRYPT_FAILED );

		error( "%d RSA_private_decrypt failed\n",
				EC_RSA_PRIVATE_DECRYPT_FAILED );
	}
};

struct RsaVerifyFailed
	: public UserError
{
	RsaVerifyFailed( long errorCode )
		: errorCode(errorCode) {}

	long errorCode;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_RSA_VERIFY_FAILED );

		error( "%d RSA_verify failed\n",
				EC_RSA_VERIFY_FAILED );
	}
};

struct NoPrimaryNetwork
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_NO_PRIMARY_NETWORK );

		error( "%d primary network not found\n",
				EC_NO_PRIMARY_NETWORK );
	}

};

struct PutKeyFetchError
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_PUT_KEY_FETCH_ERROR );

		error( "%d error fetching current put key\n",
				EC_PUT_KEY_FETCH_ERROR );
	}

};

struct IdentityHashInvalid
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_IDENTITY_HASH_INVALID );

		error( "%d identity hash not valid\n",
				EC_IDENTITY_HASH_INVALID );
	}

};

struct InvalidFloginToken
	: public UserError
{
	InvalidFloginToken( const char *floginToken )
		: floginToken(Pointer(floginToken)) {}
	
	String floginToken;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_INVALID_FLOGIN_TOKEN );

		error( "%d supplied ftoken is not valid\n",
				EC_INVALID_FLOGIN_TOKEN );
	}
};

struct FtokenRequestInvalid
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_INVALID_FTOKEN_REQUEST );

		error( "%d supplied ftoken is not valid\n",
				EC_INVALID_FTOKEN_REQUEST );
	}

};

struct FloginTokenWrongSize
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_FLOGIN_TOKEN_WRONG_SIZE );

		error( "%d flogin token is the wrong size\n",
				EC_FLOGIN_TOKEN_WRONG_SIZE );
	}

};

struct TokenWrongSize
	: public UserError
{
	TokenWrongSize( long expected, long got )
		: expected(expected), got(got) {}

	long expected;
	long got;
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_TOKEN_WRONG_SIZE );

		error( "%d token is the wrong size, expected %ld got %ld\n",
				EC_TOKEN_WRONG_SIZE, expected, got );
	}

};

struct BroadcastRecipientInvalid
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_BROADCAST_RECIPIENT_INVALID );

		error( "%d broadcast recpient invalid\n",
				EC_BROADCAST_RECIPIENT_INVALID );
	}
};

struct RequestIdInvalid
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_REQUEST_ID_INVALID );

		error( "%d request id invalid\n",
				EC_REQUEST_ID_INVALID );
	}
};

struct LoginTokenNotValid
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_LOGIN_TOKEN_INVALID );

		error( "%d login token not valid\n",
				EC_LOGIN_TOKEN_INVALID );
	}
};

struct NotImplemented
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_NOT_IMPLEMENTED );

		error( "%d function not implemented\n",
				EC_NOT_IMPLEMENTED );
	}
};

struct MissingKeys
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_MISSING_KEYS );

		error( "%d missing keys\n",
				EC_MISSING_KEYS );
	}
};

struct VersionAlreadyGiven
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_VERSION_ALREADY_GIVEN );

		error( "%d version already given\n",
				EC_VERSION_ALREADY_GIVEN );
	}
};

struct DatabaseConnectionFailed
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_DATABASE_CONNECTION_FAILED );

		error( "%d failed to connect to the database\n",
				EC_DATABASE_CONNECTION_FAILED );
	}
};

struct NoCommonVersion
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_NO_COMMON_VERSION );

		error( "%d no common version\n",
				EC_NO_COMMON_VERSION );
	}
};

struct InvalidCommKey
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_INVALID_COMM_KEY );

		error( "%d invalid communication key\n",
				EC_INVALID_COMM_KEY );
	}
};

struct BadHost
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_BAD_HOST );

		error( "%d bad host\n",
				EC_BAD_HOST );
	}
};

struct BadSite
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_BAD_SITE );

		error( "%d bad site\n",
				EC_BAD_SITE );
	}
};

struct ExpectedTls
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_EXPECTED_TLS );

		error( "%d expecting tls\n",
				EC_EXPECTED_TLS );
	}
};

struct ExpectedLocalKey
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_EXPECTED_LOCAL_KEY );

		error( "%d expecting local key\n",
				EC_EXPECTED_LOCAL_KEY );
	}
};

struct Base64ParseError
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_BASE64_PARSE_ERROR );

		error( "%d Base64 parse error\n",
				EC_BASE64_PARSE_ERROR );
	}
};

struct ParseBufferExhausted
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_PARSE_BUFFER_EXHAUSTED );

		error( "%d parse buffer exhausted\n",
				EC_PARSE_BUFFER_EXHAUSTED );
	}
};

struct WriteError
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_WRITE_ERROR );

		error( "%d write error\n",
				EC_WRITE_ERROR );
	}
};

struct DaemonToDaemonTimeout
	: public UserError
{
	DaemonToDaemonTimeout( const char *src, int line )
		: src(Pointer(src)), line(line) {}

	String src;
	int line;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_DAEMON_DAEMON_TIMEOUT );

		error( "%d daemon-daemon timeout: %s line %d\n",
				EC_DAEMON_DAEMON_TIMEOUT, src(), line );
	}
};
	
struct SslFailedToLoad
	: public UserError
{
	SslFailedToLoad( const char *file )
		: file(Pointer(file))
	{}

	String file;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SSL_FAILED_TO_LOAD );

		error( "%d ssl failed to load file %s\n",
				EC_SSL_FAILED_TO_LOAD, file() );
	}
};

struct SslParamNotSet
	: public UserError
{
	SslParamNotSet( const char *param )
		: param(Pointer(param))
	{}

	String param;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SSL_PARAM_NOT_SET );

		error( "%d ssl configuration parameter %s was not set\n",
				EC_SSL_PARAM_NOT_SET, param() );
	}
};

struct SslContextCreationFailed
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SSL_CONTEXT_CREATION_FAILED );

		error( "%d ssl context creation failed\n",
				EC_SSL_CONTEXT_CREATION_FAILED );
	}
};

struct DbQueryFailed
	: public UserError
{
	DbQueryFailed( const char *query, const char *reason )
		: query(Pointer(query)), reason(Pointer(reason)) {}

	String query;
	String reason;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_DSNPD_DB_QUERY_FAILED );

		error( "%d mysql_query failed: %s QUERY: %s\n", 
				EC_DSNPD_DB_QUERY_FAILED, reason(), query() );
	}
};

struct SchemaVersionMismatch
	: public UserError
{
	SchemaVersionMismatch( int databaseVersion, int softwareVersion )
	:
		databaseVersion( databaseVersion ),
		softwareVersion( softwareVersion )
	{}

	int databaseVersion;
	int softwareVersion;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SCHEMA_VERSION_MISMATCH, databaseVersion, softwareVersion );

		error( "%d schema version mismatch: database at version %d, software at version %d\n", 
				EC_SCHEMA_VERSION_MISMATCH, databaseVersion, softwareVersion );
	}
};

struct InvalidLoginToken
	: public UserError
{
	InvalidLoginToken( const char *loginToken )
		: loginToken(Pointer(loginToken)) {}

	String loginToken;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_INVALID_LOGIN_TOKEN );

		error( "%d supplied token %s is not valid\n",
				EC_INVALID_LOGIN_TOKEN, loginToken() );
	}
};

struct SockAddrError
	: public UserError
{
	SockAddrError( int err )
		: err(err) {}

	int err;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SOCKADDR_ERROR );

		error( "%d error getting socket name, errno %d\n",
				EC_SOCKADDR_ERROR, errno );
	}
};

struct SockNotLocal
	: public UserError
{
	SockNotLocal( int sock )
		: sock(sock) {}

	int sock;

	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_SOCK_NOT_LOCAL );

		error( "%d socket %d not local\n",
				EC_SOCK_NOT_LOCAL, sock );
	}
};

struct ConfigParseError
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_CONF_PARSE_ERROR );

		error( "%d config parse error\n",
				EC_CONF_PARSE_ERROR );
	}
};

struct InvalidRemoteBroadcastRequest
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_INVALID_REMOTE_BR_REQ );

		error( "%d invalid remote broadcast request\n",
				EC_INVALID_REMOTE_BR_REQ );
	}
};

struct InvalidRemoteBroadcastResponse
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_INVALID_REMOTE_BR_RSP );

		error( "%d invalid remote broadcast response\n",
				EC_INVALID_REMOTE_BR_RSP );
	}
};

struct InvalidRemoteBroadcastSubject
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_INVALID_REMOTE_BR_SUBJ );

		error( "%d invalid remote broadcast subject\n",
				EC_INVALID_REMOTE_BR_SUBJ );
	}
};

struct WriteOnNullSocketBio
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_WRITE_ON_NULL_SOCKET_BIO );

		error( "%d write on null socket bio\n",
				EC_WRITE_ON_NULL_SOCKET_BIO );
	}
};

struct WrongNumberOfRelids
	: public UserError
{
	virtual void print( BioWrap &bio )
	{
		bio.returnError( EC_WRONG_NUMBER_OF_RELIDS );

		error( "%d wrong number of relids\n",
				EC_WRONG_NUMBER_OF_RELIDS );
	}
};

#endif
