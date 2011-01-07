/*
 * Copyright (c) 2008-2010, Adrian Thurston <thurston@complang.org>
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

#include "dsnp.h"
#include "encrypt.h"
#include "string.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

long checkFriendClaim( IdentityOrig &identity, MYSQL *mysql, const char *user, 
		const char *friendHash )
{
	DbQuery check( mysql,
		"SELECT iduri FROM friend_claim WHERE user = %e AND friend_hash = %e",
		user, friendHash );

	if ( check.rows() != 0 ) {
		MYSQL_ROW row = check.fetchRow();
		identity.identity = strdup( row[0] );
		identity.parse();
		return 1;
	}

	return 0;
}

char *userIdentityHash( MYSQL *mysql, const char *user )
{
	DbQuery salt( mysql,
		"SELECT id_salt FROM user WHERE user = %e", user );

	if ( salt.rows() > 0  ) {
		MYSQL_ROW row = salt.fetchRow();
		String identity( "%s%s/", c->CFG_URI, user );
		return makeIdHash( row[0], identity.data );
	}

	return 0;
}

void ftokenRequest( MYSQL *mysql, const char *_user, const char *hash )
{
	/* Load user, identity and friend claim. */
	User user( mysql, _user );
	Identity identity( mysql, Identity::ByHash(), hash );
	FriendClaim friendClaim( mysql, user, identity );

	/* Get the public key for the identity. */
	Keys *idPub = identity.fetchPublicKey();

	/* Load the private key for the user. */
	Keys *userPriv = loadKey( mysql, user.user() );

	/* Generate the login request id and relationship and request ids. */
	unsigned char flogin_token[TOKEN_SIZE], reqidBin[REQID_SIZE];
	RAND_bytes( flogin_token, TOKEN_SIZE );
	RAND_bytes( reqidBin, REQID_SIZE );

	Encrypt encrypt;
	encrypt.load( idPub, userPriv );

	/* Encrypt it. */
	int sigRes = encrypt.signEncrypt( flogin_token, TOKEN_SIZE );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}

	/* Store the request. */
	char *flogin_token_str = binToBase64( flogin_token, TOKEN_SIZE );
	String reqid = binToBase64( reqidBin, REQID_SIZE );

	DbQuery( mysql,
		"INSERT INTO ftoken_request "
		"( user_id, identity_id, token, reqid, msg_sym ) "
		"VALUES ( %L, %L, %e, %e, %e ) ",
		user.id(), identity.id(), flogin_token_str, reqid(), encrypt.sym );

	String userIduri( "%s%s/", c->CFG_URI, user.user() );
	String userHash = makeIduriHash( userIduri );

	/* Return the request id for the requester to use. */
	BIO_printf( bioOut, "OK %s %s %s\r\n", identity.iduri(), userHash(), reqid() );
}

void fetchFtoken( MYSQL *mysql, const char *reqid )
{
	DbQuery ftoken( mysql,
		"SELECT msg_sym FROM ftoken_request WHERE reqid = %e", reqid );

	if ( ftoken.rows() > 0 ) {
		MYSQL_ROW row = ftoken.fetchRow();
		BIO_printf( bioOut, "OK %s\r\n", row[0] );
	}
	else {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_NO_FTOKEN );
	}
}

void ftokenResponse( MYSQL *mysql, const char *_user, const char *hash, 
		const char *flogin_reqid_str )
{
	/*
	 * a) checks that $FR-URI is a friend
	 * b) if browser is not logged in fails the process (no redirect).
	 * c) fetches $FR-URI/tokens/$FR-RELID.asc
	 * d) decrypts and verifies the token
	 * e) redirects the browser to $FP-URI/submit-token?uri=$URI&token=$TOK
	 */

	/* Load user, identity and friend claim. */
	User user( mysql, _user );
	Identity identity( mysql, Identity::ByHash(), hash );
	FriendClaim friendClaim( mysql, user, identity );

	/* Get the public key for the identity. */
	Keys *idPub = identity.fetchPublicKey();

	RelidEncSig encsig;
	fetchFtokenNet( encsig, identity.site(), identity.host(), flogin_reqid_str );

	/* Load the private key for the user the request is for. */
	Keys *userPriv = loadKey( mysql, user.user() );

	Encrypt encrypt;
	encrypt.load( idPub, userPriv );

	/* Decrypt the flogin_token. */
	int verifyRes = encrypt.decryptVerify( encsig.sym );
	if ( verifyRes < 0 ) {
		message("ftoken_response: ERROR_DECRYPT_VERIFY\n" );
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPT_VERIFY );
		return;
	}

	/* Check the size. */
	if ( encrypt.decLen != REQID_SIZE ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPTED_SIZE );
		return;
	}

	unsigned char *flogin_token = encrypt.decrypted;
	char *flogin_token_str = binToBase64( flogin_token, RELID_SIZE );

	DbQuery( mysql,
		"INSERT INTO remote_flogin_token "
		"( user_id, identity_id, login_token ) "
		"VALUES ( %L, %L, %e )",
		user.id(), identity.id(), flogin_token_str );

	/* Return the login token for the requester to use. */
	BIO_printf( bioOut, "OK %s %s\r\n", identity.iduri(), flogin_token_str );
}

void submitFtoken( MYSQL *mysql, const char *token )
{
	long lasts = LOGIN_TOKEN_LASTS;

	DbQuery request( mysql,
		"SELECT user_id, identity_id "
		"FROM ftoken_request "
		"WHERE token = %e",
		token );

	if ( request.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}
	MYSQL_ROW row = request.fetchRow();
	long long userId = parseId( row[0] );
	long long identityId = parseId( row[1] );

	Identity identity( mysql, identityId );

	DbQuery( mysql, 
		"INSERT INTO flogin_token ( user_id, identity_id, login_token, expires ) "
		"VALUES ( %L, %L, %e, date_add( now(), interval %l second ) )", 
		userId, identityId, token, lasts );

	String hash = makeIduriHash( identity.iduri() );

	BIO_printf( bioOut, "OK %s %s %ld\r\n", identity.iduri(), hash(), lasts );
}



