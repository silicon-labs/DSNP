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
#include "error.h"

#include <mysql/mysql.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

bool checkFriendClaimExists( MYSQL *mysql, User &user, Identity &identity )
{
	/* Check to see if there is already a friend claim. */
	DbQuery claim( mysql, 
		"SELECT id "
		"FROM friend_claim "
		"WHERE user_id = %L AND identity_id = %L",
		user.id(), identity.id() );

	if ( claim.rows() != 0 )
		return true;

	return false;
}

bool checkFriendRequestExists( MYSQL *mysql, User &user, Identity &identity )
{
	/* Check to see if there is already a friend claim. */
	DbQuery claim( mysql, 
		"SELECT id "
		"FROM friend_request "
		"WHERE user_id = %L AND identity_id = %L",
		user.id(), identity.id() );

	if ( claim.rows() != 0 )
		return true;

	return false;
}

void relidRequest( MYSQL *mysql, const char *_user, const char *_iduri )
{
	/* a) verifies challenge response
	 * b) fetches $URI/id.asc (using SSL)
	 * c) randomly generates a one-way relationship id ($FR-RELID)
	 * d) randomly generates a one-way request id ($FR-REQID)
	 * e) encrypts $FR-RELID to friender and signs it
	 * f) makes message available at $FR-URI/friend-request/$FR-REQID.asc
	 * g) redirects the user's browser to $URI/return-relid?uri=$FR-URI&reqid=$FR-REQID
	 */
	
	User user( mysql, _user );
	Identity identity( mysql, _iduri );

	if ( user.id() < 0 )
		throw InvalidUser( user.user );

	/* Check to make sure this isn't ourselves. */
	String ourId( "%s%s/", c->CFG_URI, user.user() );
	if ( strcasecmp( ourId(), identity.iduri ) == 0 )
		throw CannotFriendSelf( identity.iduri );
	
	/* FIXME: these should be presented to the user only after the bounce back
	 * that authenticates the submitter, otherwise anyone can test friendship
	 * between arbitrary users. */

	/* Check for the existence of a friend claim. */
	if ( checkFriendClaimExists( mysql, user, identity ) )
		throw FriendClaimExists( user.user, identity.iduri );

	/* Check for the existence of a friend request. */
	if ( checkFriendRequestExists( mysql, user, identity ) )
		throw FriendRequestExists( user.user, identity.iduri );

	Keys *idPub = identity.fetchPublicKey();

	/* Load the private key for the user the request is for. */
	Keys *userPriv = loadKey( mysql, user );

	/* Generate the relationship and request ids. */
	unsigned char relidBin[RELID_SIZE], reqidBin[REQID_SIZE];
	RAND_bytes( relidBin, RELID_SIZE );
	RAND_bytes( reqidBin, REQID_SIZE );

	/* Encrypt and sign the relationship id. */
	Encrypt encrypt;
	encrypt.load( idPub, userPriv );
	int sigRes = encrypt.signEncrypt( relidBin, RELID_SIZE );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}
	
	/* Store the request. */
	String relid = binToBase64( relidBin, RELID_SIZE );
	String reqid = binToBase64( reqidBin, REQID_SIZE );

	message("allocated requested_relid %s for user %s\n", relid(), user.user() );

	DbQuery( mysql,
		"INSERT INTO relid_request "
		"( user_id, identity_id, requested_relid, reqid, msg_sym ) "
		"VALUES( %L, %L, %e, %e, %e )",
		user.id(), identity.id(), relid.data, reqid.data, encrypt.sym );

	/* Return the request id for the requester to use. */
	BIO_printf( bioOut, "OK %s\r\n", reqid.data );
}

void fetchRequestedRelid( MYSQL *mysql, const char *reqid )
{
	DbQuery request( mysql,
		"SELECT msg_sym FROM relid_request WHERE reqid = %e", reqid );

	/* Check for a result. */
	if ( request.rows() > 0 ) {
		MYSQL_ROW row = request.fetchRow();
		BIO_printf( bioOut, "OK %s\r\n", row[0] );
	}
	else {
		BIO_printf( bioOut, "ERROR\r\n" );
	}
}

void relidResponse( MYSQL *mysql, const char *_user, 
		const char *reqid, const char *_iduri )
{
	/*  a) verifies browser is logged in as owner
	 *  b) fetches $FR-URI/id.asc (using SSL)
	 *  c) fetches $FR-URI/friend-request/$FR-REQID.asc 
	 *  d) decrypts and verifies $FR-RELID
	 *  e) randomly generates $RELID
	 *  f) randomly generates $REQID
	 *  g) encrypts "$FR-RELID $RELID" to friendee and signs it
	 *  h) makes message available at $URI/request-return/$REQID.asc
	 *  i) redirects the friender to $FR-URI/friend-final?uri=$URI&reqid=$REQID
	 */
	
	User user( mysql, _user );
	if ( user.id() < 0 )
		throw InvalidUser( user.user );

	Identity identity( mysql, _iduri );

	/* Get the public key for the identity. */
	Keys *idPub = identity.fetchPublicKey();

	RelidEncSig encsig;
	fetchRequestedRelidNet( encsig, identity.site(),
			identity.host(), reqid );

	/* Load the private key for the user the request is for. */
	Keys *userPriv = loadKey( mysql, user );

	/* Decrypt and verify the requested_relid. */
	Encrypt encrypt;
	encrypt.load( idPub, userPriv );


	int verifyRes = encrypt.decryptVerify( encsig.sym );
	if ( verifyRes < 0 ) {
		::message("relid_response: ERROR_DECRYPT_VERIFY\n" );
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPT_VERIFY );
		return;
	}

	/* Verify the message is the right size. */
	if ( encrypt.decLen != RELID_SIZE ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPTED_SIZE );
		return;
	}

	/* This should not be deleted as long as we don't do any more decryption. */
	unsigned char *requested_relid = encrypt.decrypted;
	
	/* Generate the relationship and request ids. */
	unsigned char response_relid[RELID_SIZE], response_reqid[REQID_SIZE];
	RAND_bytes( response_relid, RELID_SIZE );
	RAND_bytes( response_reqid, REQID_SIZE );

	unsigned char message[RELID_SIZE*2];
	memcpy( message, requested_relid, RELID_SIZE );
	memcpy( message+RELID_SIZE, response_relid, RELID_SIZE );

	/* Encrypt and sign using the same credentials. */
	int sigRes = encrypt.signEncrypt( message, RELID_SIZE*2 );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}

	/* Store the request. */
	char *requested_relid_str = binToBase64( requested_relid, RELID_SIZE );
	char *response_relid_str = binToBase64( response_relid, RELID_SIZE );
	char *response_reqid_str = binToBase64( response_reqid, REQID_SIZE );

	::message( "allocated response relid %s for user %s\n", response_relid_str, user.user() );
	
	/* Record the response, which will be fetched. */
	DbQuery( mysql,
		"INSERT INTO relid_response "
		"( identity_id, requested_relid, returned_relid, reqid, msg_sym ) "
		"VALUES ( %L, %e, %e, %e, %e )",
		identity.id(), requested_relid_str, response_relid_str, 
		response_reqid_str, encrypt.sym );

	Relationship relationship( mysql, user, REL_TYPE_FRIEND, identity );

	/* Recored the sent request. */
	DbQuery( mysql, 
		"INSERT INTO sent_friend_request "
		"( user_id, identity_id, relationship_id, requested_relid, returned_relid ) "
		"VALUES ( %L, %L, %L, %e, %e );",
		user.id(), identity.id(), relationship.id(), requested_relid_str, response_relid_str );

	String args( "sent_friend_request %s %s", user.user(), identity.iduri() );
	appNotification( args, 0, 0 );
	
	/* Return the request id for the requester to use. */
	BIO_printf( bioOut, "OK %s\r\n", response_reqid_str );

	delete[] requested_relid_str;
	delete[] response_relid_str;
	delete[] response_reqid_str;
}

void fetchResponseRelid( MYSQL *mysql, const char *reqid )
{
	/* Execute the query. */
	DbQuery response( mysql,
		"SELECT msg_sym FROM relid_response WHERE reqid = %e;", reqid );
	
	/* Check for a result. */
	if ( response.rows() ) {
		MYSQL_ROW row = response.fetchRow();
		BIO_printf( bioOut, "OK %s\r\n", row[0] );
	}
	else {
		BIO_printf( bioOut, "ERR\r\n" );
	}
}

long verifyReturnedFrRelid( MYSQL *mysql, unsigned char *fr_relid )
{
	char *requested_relid_str = binToBase64( fr_relid, RELID_SIZE );
	DbQuery request( mysql,
		"SELECT id FROM relid_request WHERE requested_relid = %e", 
		requested_relid_str );

	/* Check for a result. */
	if ( request.rows() )
		return 1;

	return 0;
}

void friendFinal( MYSQL *mysql, const char *_user, 
		const char *reqid_str, const char *_iduri )
{
	/* a) fetches $URI/request-return/$REQID.asc 
	 * b) decrypts and verifies message, must contain correct $FR-RELID
	 * c) stores request for friendee to accept/deny
	 */

	User user( mysql, _user );
	if ( user.id() < 0 )
		throw InvalidUser( user.user );

	Identity identity( mysql, _iduri );

	/* Get the public key for the identity. */
	Keys *id_pub = identity.fetchPublicKey();
	if ( id_pub == 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_PUBLIC_KEY );
		return;
	}

	RelidEncSig encsig;
	int fetchRes = fetchResponseRelidNet( encsig, identity.site(), 
			identity.host(), reqid_str );
	if ( fetchRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_FETCH_RESPONSE_RELID );
		return;
	}
	
	/* Load the private key for the user the request is for. */
	Keys *user_priv = loadKey( mysql, user );

	Encrypt encrypt;
	encrypt.load( id_pub, user_priv );

	int verifyRes = encrypt.decryptVerify( encsig.sym );
	if ( verifyRes < 0 ) {
		::message("friend_final: ERROR_DECRYPT_VERIFY\n" );
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPT_VERIFY );
		return;
	}

	/* Verify that the message is the right size. */
	if ( encrypt.decLen != RELID_SIZE*2 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPTED_SIZE );
		return;
	}

	unsigned char *message = encrypt.decrypted;

	unsigned char requested_relid[RELID_SIZE], returned_relid[RELID_SIZE];
	memcpy( requested_relid, message, RELID_SIZE );
	memcpy( returned_relid, message+RELID_SIZE, RELID_SIZE );

	verifyRes = verifyReturnedFrRelid( mysql, requested_relid );
	if ( verifyRes != 1 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_REQUESTED_RELID_MATCH );
		return;
	}
		
	char *requested_relid_str = binToBase64( requested_relid, RELID_SIZE );
	char *returned_relid_str = binToBase64( returned_relid, RELID_SIZE );

	/* Make a user request id. */
	unsigned char user_reqid[REQID_SIZE];
	RAND_bytes( user_reqid, REQID_SIZE );
	char *user_reqid_str = binToBase64( user_reqid, REQID_SIZE );

	Relationship relationship( mysql, user, REL_TYPE_FRIEND, identity );

	DbQuery( mysql, 
		"INSERT INTO friend_request "
		" ( user_id, identity_id, relationship_id, reqid, requested_relid, returned_relid ) "
		" VALUES ( %L, %L, %L, %e, %e, %e ) ",
		user.id(), identity.id(), relationship.id(), user_reqid_str, requested_relid_str, returned_relid_str );
	
	String args( "friend_request %s %s %s %s %s",
		user.user(), identity.iduri(), user_reqid_str, requested_relid_str, returned_relid_str );
	appNotification( args, 0, 0 );
	
	/* Return the request id for the requester to use. */
	BIO_printf( bioOut, "OK\r\n" );

	delete[] requested_relid_str;
	delete[] returned_relid_str;
}
