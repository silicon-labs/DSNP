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

void userMessage( MYSQL *mysql, const char *user, const char *friendId,
		const char *date, const char *msg, long length )
{
	String args( "notification_message %s %s %s %ld", 
			user, friendId, date, length );
	appNotification( args, msg, length );
}

void sendMessageNow( MYSQL *mysql, bool prefriend, const char *user,
		const char *toIdentity, const char *putRelid,
		const char *msg, char **resultMsg )
{
	Keys *idPub = fetchPublicKey( mysql, toIdentity );
	Keys *userPriv = loadKey( mysql, user );

	Encrypt encrypt;
	encrypt.load( idPub, userPriv );

	/* Include the null in the message. */
	encrypt.signEncrypt( (u_char*)msg, strlen(msg) );

	message( "send_message_now sending to: %s\n", toIdentity );
	sendMessageNet( mysql, prefriend, user, toIdentity,
			putRelid, encrypt.sym, strlen(encrypt.sym), resultMsg );
}


void addGetBroadcastKey( MYSQL *mysql, long long friendClaimId, long long networkId, long long generation )
{
	DbQuery check( mysql,
		"INSERT IGNORE INTO get_broadcast_key ( friend_claim_id, network_id, generation ) "
		"VALUES ( %L, %L, %L )",
		friendClaimId, networkId, generation );
}

void Server::storeBroadcastKey( MYSQL *mysql, User &user, Identity &identity, FriendClaim &friendClaim,
		const char *distName, long long generation, const char *broadcastKey )
{
	DbQuery( mysql, 
			"INSERT IGNORE INTO get_broadcast_key "
			"( "
			"	friend_claim_id, network_dist, "
			"	generation, broadcast_key "
			") "
			"VALUES ( %L, %e, %L, %e )",
			friendClaim.id, distName, generation, broadcastKey );

	bioWrap->printf( "OK\n" );
}

void Server::receiveMessage( MYSQL *mysql, const char *relid, const char *msg )
{
	FriendClaim friendClaim( mysql, relid );

	User user( mysql, friendClaim.userId );
	Identity identity( mysql, friendClaim.identityId );

	Keys *userPriv = loadKey( mysql, user );
	Keys *idPub = identity.fetchPublicKey();

	Encrypt encrypt( idPub, userPriv );
	encrypt.decryptVerify( msg );

	MessageParser mp;
	mp.parse( (char*)encrypt.decrypted, encrypt.decLen );

	switch ( mp.type ) {
		case MessageParser::BroadcastKey:
			storeBroadcastKey( mysql, user, identity, friendClaim,
					mp.distName, mp.generation, mp.key );
			break;
		case MessageParser::EncryptRemoteBroadcast: 
			encryptRemoteBroadcast( mysql, user, identity, mp.token,
					mp.seq_num, mp.embeddedMsg, mp.length );
			break;
		case MessageParser::ReturnRemoteBroadcast:
			returnRemoteBroadcast( mysql, user, identity, mp.reqid,
					mp.network, mp.generation, mp.sym );
			break;
		case MessageParser::UserMessage:
		default:
//			userMessage( mysql, user, friendId, mp.date, mp.embeddedMsg, mp.length );
			throw NotImplemented();
			break;
	}
}

void Server::submitMessage( MYSQL *mysql, const char *user, const char *toIdentity, const char *msg, long mLen )
{
	String timeStr = timeNow();

	/* Make the full message. */
	String command( "user_message %s %ld\r\n", timeStr.data, mLen );
	String full = addMessageData( command, msg, mLen );

	queueMessage( mysql, user, toIdentity, full.data, full.length );
	bioWrap->printf( "OK\r\n" );
}

