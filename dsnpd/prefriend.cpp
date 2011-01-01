/*
 * Copyright (c) 2008-2009, Adrian Thurston <thurston@complang.org>
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

#include <string.h>

void deleteFriendRequest( MYSQL *mysql, const char *user, const char *user_reqid )
{
	/* Insert the friend claim. */
	DbQuery( mysql, 
		"DELETE FROM friend_request WHERE for_user = %e AND reqid = %e;",
		user, user_reqid );
}

long long storeFriendClaim( MYSQL *mysql, const char *user, 
		const char *identity, const char *putRelid, const char *getRelid )
{
	char *friendHashStr = makeIduriHash( identity );
	IdentityOrig fr(identity);
	fr.parse();

	DbQuery findUser( mysql, "SELECT id FROM user WHERE user = %e", user );
	long long userId = strtoll( findUser.fetchRow()[0], 0, 10 );

	/* Insert the friend claim. */
	DbQuery( mysql, "INSERT INTO friend_claim "
		"( user, user_id, iduri, "
		"	friend_hash, put_relid, get_relid, name ) "
		"VALUES ( %e, %L, %e, %e, %e, %e, %e );",
		user, userId, identity, friendHashStr, putRelid, getRelid, fr.user );

	/* Get the id that was assigned to the message. */
	DbQuery lastInsertId( mysql, "SELECT last_insert_id()" );
	if ( lastInsertId.rows() != 1 )
		return -1;

	return strtoll( lastInsertId.fetchRow()[0], 0, 10 );
}

long notifyAccept( MYSQL *mysql, User &user, Identity &identity,
		const String &requestedRelid, const String &returnedRelid )
{
	/* Verify that there is a friend request. */
	DbQuery checkSentRequest( mysql, 
		"SELECT id FROM sent_friend_request "
		"WHERE user_id = %L AND identity_id = %L AND requested_relid = %e and returned_relid = %e",
		user.id(), identity.id(), requestedRelid(), returnedRelid() );

	if ( checkSentRequest.rows() != 1 )
		throw FriendRequestInvalid();

	Keys *userPriv = loadKey( mysql, user.user() );
	Keys *idPub = identity.fetchPublicKey();

#if 0
	/* The relid is the one we made on this end. It becomes the put_relid. */
	const char *putRelid = requested_relid;
	const char *getRelid = returned_relid;
	storeFriendClaim( mysql, forUser, from_id, putRelid, getRelid );

	/* Clear the sent_freind_request. */
	DbQuery salt( mysql, "SELECT id_salt FROM user WHERE user = %e", forUser );

	/* Check for a result. */
	if ( salt.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR request not found\r\n" );
		return 0;
	}
	MYSQL_ROW row = salt.fetchRow();
	const char *returned_id_salt = row[0];
	String resultCommand( "notify_accept_result %s\r\n", returned_id_salt );

	Encrypt encrypt( id_pub, user_priv );
	encrypt.signEncrypt( (u_char*)resultCommand(), resultCommand.length+1 );

	BIO_printf( bioOut, "RESULT %ld\r\n", strlen(encrypt.sym) );
	BIO_write( bioOut, encrypt.sym, strlen(encrypt.sym) );
#endif

	return 0;
}

long registered( MYSQL *mysql, const char *forUser, const char *from_id,
		const char *requested_relid, const char *returned_relid )
{
	DbQuery removeSentRequest( mysql, 
		"DELETE FROM sent_friend_request "
		"WHERE from_user = %e AND for_id = %e AND requested_relid = %e AND "
		"	returned_relid = %e",
		forUser, from_id, requested_relid, returned_relid );
	
	BIO_printf( bioOut, "OK\r\n" );

	String args( "sent_friend_request_accepted %s %s", forUser, from_id );
	appNotification( args, 0, 0 );

	addToNetwork( mysql, forUser, "-", from_id );

	return 0;
}

void notifyAcceptReturnedIdSalt( MYSQL *mysql, const char *user, const char *user_reqid, 
		const char *from_id, const char *requested_relid, 
		const char *returned_relid, const char *returned_id_salt )
{
	message( "accept_friend received: %s\n", returned_id_salt );

	/* The friendship has been accepted. Store the claim. */
	const char *putRelid = returned_relid;
	const char *getRelid = requested_relid;
	storeFriendClaim( mysql, user, from_id, putRelid, getRelid );

	/* Notify the requester. */
	String registered( "registered %s %s\r\n", 
			requested_relid, returned_relid );
	sendMessageNow( mysql, true, user, from_id, requested_relid, registered.data, 0 );

	/* Remove the user friend request. */
	deleteFriendRequest( mysql, user, user_reqid );

	String args( "friend_request_accepted %s %s", user, from_id );
	appNotification( args, 0, 0 );

	addToNetwork( mysql, user, "-", from_id );

	BIO_printf( bioOut, "OK\r\n" );
}

void prefriendMessage( MYSQL *mysql, const char *relid, const char *msg )
{
	DbQuery sent( mysql, 
		"SELECT user_id, identity_id FROM sent_friend_request "
		"WHERE requested_relid = %e",
		relid );

	if ( sent.rows() == 0 ) {
		error("prefriend_message: could not locate friend via sent_friend_request\n");
		BIO_printf( bioOut, "ERROR finding friend\r\n" );
		return;
	}

	MYSQL_ROW row = sent.fetchRow();
	long long userId = strtoll( row[0], 0, 10 );
	long long identityId = strtoll( row[1], 0, 10 );

	User user( mysql, userId );
	Identity identity( mysql, identityId );

	Keys *userPriv = loadKey( mysql, user.user );
	Keys *idPub = identity.fetchPublicKey();

	Encrypt encrypt( idPub, userPriv );
	int decryptRes = encrypt.decryptVerify( msg );

	if ( decryptRes < 0 )
		throw DecryptVerifyFailed();

	PrefriendParser pfp;
	pfp.parse( (char*)encrypt.decrypted, encrypt.decLen );
	switch ( pfp.type ) {
		case PrefriendParser::NotifyAccept:
			notifyAccept( mysql, user, identity,
					pfp.requestedRelid, pfp.returnedRelid );
			break;
		case PrefriendParser::Registered:
			registered( mysql, user.user, identity.iduri,
					pfp.requestedRelid, pfp.returnedRelid  );
			break;
		default:
			break;
	}
}

void acceptFriend( MYSQL *mysql, const char *_user, const char *userReqid )
{
	User user( mysql, _user );
	if ( user.id() < 0 )
		throw InvalidUser( user.user );

	/* Find the friend request. */
	DbQuery friendRequest( mysql, 
		"SELECT identity_id, requested_relid, returned_relid "
		"FROM friend_request "
		"WHERE user_id = %L AND reqid = %e;",
		user.id(), userReqid );

	/* Check for a result. */
	if ( friendRequest.rows() == 0 )
		throw FriendRequestInvalid();

	MYSQL_ROW row = friendRequest.fetchRow();
	long long identityId = strtoll( row[0], 0, 10 );
	char *requestedRelid = row[1];
	char *returnedRelid = row[2];

	Identity identity( mysql, identityId );

	/* Notify the requester. */
	String buf( "notify_accept %s %s\r\n", requestedRelid, returnedRelid );

	char *resultMessage = 0;
	int nfa = sendMessageNow( mysql, true, user.user, identity.iduri, requestedRelid, buf(), &resultMessage );

	if ( nfa < 0 ) {
		BIO_printf( bioOut, "ERROR accept failed with %d\r\n", nfa );
		return;
	}

	NotifyAcceptResultParser narp;
	narp.parse( resultMessage, strlen(resultMessage) );
	switch ( narp.type ) {
		case NotifyAcceptResultParser::NotifyAcceptResult:
			notifyAcceptReturnedIdSalt( mysql, user.user, userReqid, 
				identity.iduri, requestedRelid, returnedRelid, narp.token );
			break;
		default:
			break;
	}
}

