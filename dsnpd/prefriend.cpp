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

	/* The relid is the one we made on this end. It becomes the put_relid. */
	const char *putRelid = requestedRelid;
	const char *getRelid = returnedRelid;

	Relationship relationship( mysql, user, REL_TYPE_FRIEND, identity );

	/* Insert the friend claim. */
	DbQuery( mysql, "INSERT INTO friend_claim "
		"( user_id, identity_id, relationship_id, "
		"	put_relid, get_relid ) "
		"VALUES ( %L, %L, %L, %e, %e );",
		user.id(), identity.id(), relationship.id(), putRelid, getRelid );

	/* Currently nothing to put in here. Should it be removed? */
	String resultCommand( "notify_accept_result\r\n" );

	Encrypt encrypt( idPub, userPriv );
	encrypt.signEncrypt( (u_char*)resultCommand(), resultCommand.length+1 );

	BIO_printf( bioOut, "RESULT %lu\r\n", strlen(encrypt.sym) );
	BIO_write( bioOut, encrypt.sym, strlen(encrypt.sym) );

	return 0;
}

long registered( MYSQL *mysql, User &user, Identity &identity,
		const char *requestedRelid, const char *returnedRelid )
{
	DbQuery( mysql, 
		"DELETE FROM sent_friend_request "
		"WHERE user_id = %L AND identity_id = %L AND "
		"	requested_relid = %e AND returned_relid = %e",
		user.id(), identity.id(), requestedRelid, returnedRelid );

	String args( "sent_friend_request_accepted %s %s", user.user(), identity.iduri() );
	appNotification( args, 0, 0 );

	addToPrimaryNetwork( mysql, user, identity );

	BIO_printf( bioOut, "OK\r\n" );

	return 0;
}

void notifyAcceptResult( MYSQL *mysql, User &user, Identity &identity,
		const char *userReqid, const char *requestedRelid,
		const char *returnedRelid )
{
	/* The friendship has been accepted. Store the claim. */
	const char *putRelid = returnedRelid;
	const char *getRelid = requestedRelid;

	Relationship relationship( mysql, user, REL_TYPE_FRIEND, identity );

	/* Insert the friend claim. */
	DbQuery( mysql, "INSERT INTO friend_claim "
		"( user_id, identity_id, relationship_id, "
		"	put_relid, get_relid ) "
		"VALUES ( %L, %L, %L, %e, %e );",
		user.id(), identity.id(), relationship.id(), putRelid, getRelid );

	/* Notify the requester. */
	String registered( "registered %s %s\r\n", requestedRelid, returnedRelid );
	sendMessageNow( mysql, true, user.user(), identity.iduri(), requestedRelid, registered(), 0 );

	DbQuery( mysql, 
		"DELETE FROM friend_request WHERE user_id = %L AND reqid = %e;",
		user.id(), userReqid );

	String args( "friend_request_accepted %s %s", user.user(), identity.iduri() );
	appNotification( args, 0, 0 );

	addToPrimaryNetwork( mysql, user, identity );

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
			registered( mysql, user, identity,
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

	/* FIXME: try, catch. */
	sendMessageNow( mysql, true, user.user, identity.iduri, requestedRelid, buf(), &resultMessage );

	NotifyAcceptResultParser narp;
	narp.parse( resultMessage, strlen(resultMessage) );
	switch ( narp.type ) {
		case NotifyAcceptResultParser::NotifyAcceptResult:
			notifyAcceptResult( mysql, user, identity, 
				userReqid, requestedRelid, returnedRelid );
			break;
		default:
			break;
	}
}

