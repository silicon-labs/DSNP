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
#include "disttree.h"

#include <string.h>

void deleteFriendRequest( MYSQL *mysql, const char *user, const char *user_reqid )
{
	/* Insert the friend claim. */
	DbQuery( mysql, 
		"DELETE FROM friend_request WHERE for_user = %e AND reqid = %e;",
		user, user_reqid );
}

long long storeFriendClaim( MYSQL *mysql, const char *user, 
		const char *identity, const char *id_salt, const char *put_relid, const char *get_relid )
{
	char *friend_hash_str = make_id_hash( id_salt, identity );

	/* Insert the friend claim. */
	DbQuery( mysql, "INSERT INTO friend_claim "
		"( user, friend_id, friend_salt, friend_hash, put_relid, get_relid ) "
		"VALUES ( %e, %e, %e, %e, %e, %e );",
		user, identity, id_salt, friend_hash_str, put_relid, get_relid );

	/* Get the id that was assigned to the message. */
	DbQuery lastInsertId( mysql, "SELECT last_insert_id()" );
	if ( lastInsertId.rows() != 1 )
		return -1;

	return strtoll( lastInsertId.fetchRow()[0], 0, 10 );
}

long notify_accept( MYSQL *mysql, const char *for_user, const char *from_id,
		const char *id_salt, const char *requested_relid, const char *returned_relid )
{
	/* Verify that there is a friend request. */
	DbQuery checkSentRequest( mysql, 
		"SELECT from_user FROM sent_friend_request "
		"WHERE from_user = %e AND for_id = %e AND requested_relid = %e and returned_relid = %e",
		for_user, from_id, requested_relid, returned_relid );

	if ( checkSentRequest.rows() != 1 ) {
		message("accept friendship failed: could not find send_friend_request\r\n");
		BIO_printf( bioOut, "ERROR request not found\r\n");
		return 0;
	}

	RSA *user_priv = load_key( mysql, for_user );
	RSA *id_pub = fetch_public_key( mysql, from_id );

	/* The relid is the one we made on this end. It becomes the put_relid. */
	storeFriendClaim( mysql, for_user, from_id, 
			id_salt, returned_relid, requested_relid );

	/* Clear the sent_freind_request. */
	DbQuery salt( mysql, "SELECT id_salt FROM user WHERE user = %e", for_user );

	/* Check for a result. */
	if ( salt.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR request not found\r\n" );
		return 0;
	}
	MYSQL_ROW row = salt.fetchRow();
	const char *returned_id_salt = row[0];
	String resultCommand( "notify_accept_result %s\r\n", returned_id_salt );

	Encrypt encrypt( id_pub, user_priv );
	encrypt.signEncrypt( (u_char*)resultCommand.data, resultCommand.length+1 );

	BIO_printf( bioOut, "RESULT %d\r\n", strlen(encrypt.sym) );
	BIO_write( bioOut, encrypt.sym, strlen(encrypt.sym) );

	return 0;
}

long registered( MYSQL *mysql, const char *for_user, const char *from_id,
		const char *requested_relid, const char *returned_relid )
{
	DbQuery removeSentRequest( mysql, 
		"DELETE FROM sent_friend_request "
		"WHERE from_user = %e AND for_id = %e AND requested_relid = %e AND "
		"	returned_relid = %e",
		for_user, from_id, requested_relid, returned_relid );
	
	BIO_printf( bioOut, "OK\r\n" );

	String args( "sent_friend_request_accepted %s %s", for_user, from_id );
	app_notification( args, 0, 0 );

	return 0;
}

void prefriend_message( MYSQL *mysql, const char *relid, const char *msg )
{
	DbQuery sent( mysql, 
		"SELECT from_user, for_id FROM sent_friend_request "
		"WHERE requested_relid = %e",
		relid );

	if ( sent.rows() == 0 ) {
		message("prefriend_message: could not locate friend via sent_friend_request\n");
		BIO_printf( bioOut, "ERROR finding friend\r\n" );
		return;
	}

	MYSQL_ROW row = sent.fetchRow();
	const char *user = row[0];
	const char *friend_id = row[1];

	RSA *user_priv = load_key( mysql, user );
	RSA *id_pub = fetch_public_key( mysql, friend_id );

	Encrypt encrypt( id_pub, user_priv );
	int decrypt_res = encrypt.decryptVerify( msg );

	if ( decrypt_res < 0 ) {
		message("prefriend_message: decrypting message failed\n");
		BIO_printf( bioOut, "ERROR %s\r\n", encrypt.err );
		return;
	}

	PrefriendParser pfp;
	pfp.parse( (char*)encrypt.decrypted, encrypt.decLen );
	switch ( pfp.type ) {
		case PrefriendParser::NotifyAccept:
			notify_accept( mysql, user, friend_id, pfp.id_salt, pfp.requested_relid, pfp.returned_relid );
			break;
		case PrefriendParser::Registered:
			registered( mysql, user, friend_id, pfp.requested_relid, pfp.returned_relid  );
			break;
		default:
			break;
	}
}

void notifyAcceptReturnedIdSalt( MYSQL *mysql, const char *user, const char *user_reqid, 
		const char *from_id, const char *requested_relid, 
		const char *returned_relid, const char *returned_id_salt )
{
	message( "accept_friend received: %s\n", returned_id_salt );

	/* The friendship has been accepted. Store the claim. */
	storeFriendClaim( mysql, user, from_id, 
			returned_id_salt, requested_relid, returned_relid );

	/* Notify the requester. */
	String registered( "registered %s %s\r\n", 
			requested_relid, returned_relid );
	sendMessageNow( mysql, true, user, from_id, requested_relid, registered.data, 0 );

	/* Remove the user friend request. */
	deleteFriendRequest( mysql, user, user_reqid );

	String args( "friend_request_accepted %s %s", user, from_id );
	app_notification( args, 0, 0 );

	BIO_printf( bioOut, "OK\r\n" );
}

void accept_friend( MYSQL *mysql, const char *user, const char *user_reqid )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	char buf[2048], *result_message = 0;
	char *from_id, *requested_relid, *returned_relid;
	char *id_salt;

	/* Execute the query. */
	exec_query( mysql, "SELECT id_salt FROM user WHERE user = %e", user );

	/* Check for a result. */
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		BIO_printf( bioOut, "ERROR request not found\r\n" );
		return;
	}
	id_salt = row[0];

	/* Execute the query. */
	exec_query( mysql, "SELECT from_id, requested_relid, returned_relid "
		"FROM friend_request "
		"WHERE for_user = %e AND reqid = %e;",
		user, user_reqid );

	/* Check for a result. */
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		BIO_printf( bioOut, "ERROR request not found\r\n" );
		return;
	}

	from_id = row[0];
	requested_relid = row[1];
	returned_relid = row[2];

	/* Notify the requester. */
	sprintf( buf, "notify_accept %s %s %s\r\n", id_salt, requested_relid, returned_relid );
	message( "accept_friend sending: %s to %s from %s\n", buf, from_id, user  );
	int nfa = sendMessageNow( mysql, true, user, from_id, requested_relid, buf, &result_message );

	if ( nfa < 0 ) {
		BIO_printf( bioOut, "ERROR accept failed with %d\r\n", nfa );
		return;
	}

	NotifyAcceptResultParser narp;
	narp.parse( result_message, strlen(result_message) );
	switch ( narp.type ) {
		case NotifyAcceptResultParser::NotifyAcceptResult:
			notifyAcceptReturnedIdSalt( mysql, user, user_reqid, 
				from_id, requested_relid, returned_relid, narp.token );
			break;
		default:
			break;
	}
}

