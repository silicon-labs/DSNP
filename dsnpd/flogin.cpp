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
#include "disttree.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

long checkFriendClaim( Identity &identity, MYSQL *mysql, const char *user, 
		const char *friend_hash )
{
	long result = 0;
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql,
		"SELECT friend_id FROM friend_claim WHERE user = %e AND friend_hash = %e",
		user, friend_hash );

	if ( query_res != 0 ) {
		result = ERR_QUERY_ERROR;
		goto query_fail;
	}

	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row ) {
		identity.identity = strdup( row[0] );
		identity.parse();
		result = 1;
	}

	/* Done. */
	mysql_free_result( select_res );

query_fail:
	return result;
}

char *userIdentityHash( MYSQL *mysql, const char *user )
{
	long result = 0;
	long query_res;
	char *identity, *id_hash_str = 0;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql,
		"SELECT id_salt FROM user WHERE user = %e", user );

	if ( query_res != 0 ) {
		result = ERR_QUERY_ERROR;
		goto query_fail;
	}

	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row ) {
		identity = new char[strlen(c->CFG_URI) + strlen(user) + 2];
		sprintf( identity, "%s%s/", c->CFG_URI, user );
		id_hash_str = make_id_hash( row[0], identity );
	}

	/* Done. */
	mysql_free_result( select_res );

query_fail:
	return id_hash_str;
}


void ftokenRequest( MYSQL *mysql, const char *user, const char *hash )
{
	int sigRes;
	Keys *user_priv, *id_pub;
	unsigned char flogin_token[TOKEN_SIZE], reqid[REQID_SIZE];
	char *flogin_token_str, *reqid_str;
	long friend_claim;
	Identity friend_id;
	Encrypt encrypt;

	/* Check if this identity is our friend. */
	friend_claim = checkFriendClaim( friend_id, mysql, user, hash );
	if ( friend_claim <= 0 ) {
		message("ftoken_request: hash %s for user %s is not valid\n", hash, user );

		/* No friend claim ... send back a reqid anyways. Don't want to give
		 * away that there is no claim. FIXME: Would be good to fake this with
		 * an appropriate time delay. */
		RAND_bytes( reqid, RELID_SIZE );
		reqid_str = binToBase64( reqid, RELID_SIZE );

		/*FIXME: Hang for a bit here instead. */
		BIO_printf( bioOut, "OK %s\r\n", reqid_str );
		return;
	}

	/* Get the public key for the identity. */
	id_pub = fetchPublicKey( mysql, friend_id.identity );
	if ( id_pub == 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_PUBLIC_KEY );
		return;
	}

	/* Load the private key for the user. */
	user_priv = loadKey( mysql, user );

	/* Generate the login request id and relationship and request ids. */
	RAND_bytes( flogin_token, TOKEN_SIZE );
	RAND_bytes( reqid, REQID_SIZE );

	encrypt.load( id_pub, user_priv );

	/* Encrypt it. */
	sigRes = encrypt.signEncrypt( flogin_token, TOKEN_SIZE );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}

	/* Store the request. */
	flogin_token_str = binToBase64( flogin_token, TOKEN_SIZE );
	reqid_str = binToBase64( reqid, REQID_SIZE );

	DbQuery( mysql,
		"INSERT INTO ftoken_request "
		"( user, from_id, token, reqid, msg_sym ) "
		"VALUES ( %e, %e, %e, %e, %e ) ",
		user, friend_id.identity, flogin_token_str, reqid_str, encrypt.sym );

	message("ftoken_request: %s %s\n", reqid_str, friend_id.identity );

	/* Return the request id for the requester to use. */
	BIO_printf( bioOut, "OK %s %s %s\r\n", reqid_str,
			friend_id.identity, userIdentityHash( mysql, user ) );
}

void fetchFtoken( MYSQL *mysql, const char *reqid )
{
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql,
		"SELECT msg_sym FROM ftoken_request WHERE reqid = %e", reqid );

	/* Execute the query. */
	if ( query_res != 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DB_ERROR );
		return;
	}

	/* Check for a result. */
	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row )
		BIO_printf( bioOut, "OK %s\r\n", row[0] );
	else
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_NO_FTOKEN );

	/* Done. */
	mysql_free_result( select_res );

	message("fetch_ftoken finished\n");
}

void ftokenResponse( MYSQL *mysql, const char *user, const char *hash, 
		const char *flogin_reqid_str )
{
	/*
	 * a) checks that $FR-URI is a friend
	 * b) if browser is not logged in fails the process (no redirect).
	 * c) fetches $FR-URI/tokens/$FR-RELID.asc
	 * d) decrypts and verifies the token
	 * e) redirects the browser to $FP-URI/submit-token?uri=$URI&token=$TOK
	 */
	int verifyRes, fetchRes;
	Keys *user_priv, *id_pub;
	unsigned char *flogin_token;
	char *flogin_token_str;
	long friend_claim;
	Identity friend_id;
	char *site;
	Encrypt encrypt;

	/* Check if this identity is our friend. */
	friend_claim = checkFriendClaim( friend_id, mysql, user, hash );
	if ( friend_claim <= 0 ) {
		/* No friend claim ... we can reveal this since ftoken_response requires
		 * that the user be logged in. */
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_NOT_A_FRIEND );
		return;
	}

	/* Get the public key for the identity. */
	id_pub = fetchPublicKey( mysql, friend_id.identity );
	if ( id_pub == 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_PUBLIC_KEY );
		return;
	}

	site = get_site( friend_id.identity );

	RelidEncSig encsig;
	fetchRes = fetch_ftoken_net( encsig, site, friend_id.host, flogin_reqid_str );
	if ( fetchRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_FETCH_FTOKEN );
		return;
	}

	/* Load the private key for the user the request is for. */
	user_priv = loadKey( mysql, user );

	encrypt.load( id_pub, user_priv );

	/* Decrypt the flogin_token. */
	verifyRes = encrypt.decryptVerify( encsig.sym );
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

	flogin_token = encrypt.decrypted;
	flogin_token_str = binToBase64( flogin_token, RELID_SIZE );

	exec_query( mysql,
		"INSERT INTO remote_flogin_token "
		"( user, identity, login_token ) "
		"VALUES ( %e, %e, %e )",
		user, friend_id.identity, flogin_token_str );

	/* Return the login token for the requester to use. */
	BIO_printf( bioOut, "OK %s %s\r\n", flogin_token_str, friend_id.identity );

	free( flogin_token_str );
}

void submitFtoken( MYSQL *mysql, const char *token )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	long lasts = LOGIN_TOKEN_LASTS;
	char *user, *from_id, *hash;

	exec_query( mysql,
		"SELECT user, from_id FROM ftoken_request WHERE token = %e",
		token );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}
	user = row[0];
	from_id = row[1];

	exec_query( mysql, 
		"INSERT INTO flogin_token ( user, identity, login_token, expires ) "
		"VALUES ( %e, %e, %e, date_add( now(), interval %l second ) )", 
		user, from_id, token, lasts );

	exec_query( mysql,
		"SELECT friend_hash FROM friend_claim WHERE friend_id = %e", from_id );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}
	hash = row[0];

	BIO_printf( bioOut, "OK %s %ld %s\r\n", hash, lasts, from_id );
}



