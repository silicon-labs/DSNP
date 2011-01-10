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

	BIO_printf( bioWrap->wbio, "OK\n" );
}

int friendProofMessage( MYSQL *mysql, const char *user, long long userId, const char *friend_id,
		const char *hash, const char *network, long long generation, const char *sym )
{
//	message("calling remote broadcast from friend proof symLen %d sym %s\n", strlen(sym), sym );
//
//	long long networkId = addNetwork( mysql, userId, network );
//
//	remoteBroadcast( mysql, user, friend_id, hash, network, networkId, generation, sym, strlen(sym) );
//	BIO_printf( bioWrap->wbio, "OK\r\n" );
	return 0;
}

void Server::receiveMessage( MYSQL *mysql, const char *relid, const char *msg )
{
	FriendClaim friendClaim( mysql, relid );

	User user( mysql, friendClaim.userId );
	Identity identity( mysql, friendClaim.identityId );

	Keys *userPriv = loadKey( mysql, user );
	Keys *idPub = identity.fetchPublicKey();

	Encrypt encrypt( idPub, userPriv );
	int decryptRes = encrypt.decryptVerify( msg );

	if ( decryptRes < 0 ) {
		error("message receipt: decryption failed\n" );
		BIO_printf( bioWrap->wbio, "ERROR %s\r\n", encrypt.err );
		return;
	}

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
		case MessageParser::FriendProof:
//			friendProofMessage( mysql, user, userId, friendId, mp.hash,
//					mp.network, mp.generation, mp.sym );
			break;
		case MessageParser::UserMessage:
//			userMessage( mysql, user, friendId, mp.date, mp.embeddedMsg, mp.length );
			break;
		default:
			BIO_printf( bioWrap->wbio, "ERROR\r\n" );
			break;
	}
}

long Server::submitMessage( MYSQL *mysql, const char *user, const char *toIdentity, const char *msg, long mLen )
{
	String timeStr = timeNow();

	/* Make the full message. */
	String command( "user_message %s %ld\r\n", timeStr.data, mLen );
	String full = addMessageData( command, msg, mLen );

	long sendResult = queueMessage( mysql, user, toIdentity, full.data, full.length );
	if ( sendResult < 0 ) {
		BIO_printf( bioWrap->wbio, "ERROR\r\n" );
		return -1;
	}

	BIO_printf( bioWrap->wbio, "OK\r\n" );
	return 0;
}

