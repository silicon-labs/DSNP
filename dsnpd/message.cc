/*
 * Copyright (c) 2008-2011, Adrian Thurston <thurston@complang.org>
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
#include "packet.h"
#include "string.h"
#include "error.h"
#include "keyagent.h"

#include <string.h>

/* Not currently used. Should be. */
void Server::userMessage( MYSQL *mysql, const String &_user,
		const String &friendId, const String &body )
{
	/* FIXME: parse? */
	User user(mysql, _user);
	String site = user.site();
	notifAgent.notifMessage( site, _user, friendId, body );
}

Allocated Server::sendMessageNow( User &user,
		const char *iduri, const char *_putRelid, const String &msg )
{
	Identity identity( mysql, iduri );

	/* Include the null in the message. */
	fetchPublicKey( identity );
	String encPacket = keyAgent.signEncrypt( identity, user, msg );

	String host = Pointer( identity.host() );
	String putRelid = Pointer( _putRelid );
	return sendMessageNet( host, putRelid, encPacket );
}

void Server::storeBroadcastKey( User &user, Identity &identity, FriendClaim &friendClaim,
		const String &distName, long long generation, const String &bkKeys )
{
	DbQuery( mysql, 
			"INSERT IGNORE INTO get_broadcast_key "
			"( "
			"	friend_claim_id, network_dist, "
			"	generation "
			") "
			"VALUES ( %L, %e, %L )",
			friendClaim.id,
			distName(),
			generation );

	DbQuery findId( mysql, 
			"SELECT id FROM get_broadcast_key "
			"WHERE friend_claim_id = %L AND "
			"	network_dist = %e AND generation = %L ",
			friendClaim.id, distName(), generation );

	MYSQL_ROW row = findId.fetchRow();
	long long id = parseId( row[0] );

	keyAgent.storeGetBroadcastKey( id, bkKeys );

	bioWrap.returnOkServer();
}


void Server::receiveMessageEstablished( FriendClaim &friendClaim, const String &relid, const String &msg )
{
	User user( mysql, friendClaim.userId );
	Identity identity( mysql, friendClaim.identityId );

	/* Decrypt. */
	fetchPublicKey( identity );
	String decrypted = keyAgent.decryptVerify( identity, user, msg );

	MessageParser mp;
	mp.parse( decrypted );

	switch ( mp.type ) {
		case MessageParser::BroadcastKey:
			storeBroadcastKey( user, identity, friendClaim,
					mp.distName, mp.generation, mp.body );
			break;
		case MessageParser::EncryptRemoteBroadcastAuthor: 
			encryptRemoteBroadcastAuthor( user, identity, friendClaim,
					mp.reqid, mp.token, mp.distName, mp.generation, mp.recipients, mp.body );
			break;
		case MessageParser::EncryptRemoteBroadcastSubject: 
			encryptRemoteBroadcastSubject( user, identity, friendClaim,
					mp.reqid, mp.hash, mp.distName, mp.generation, mp.recipients, mp.body );
			break;
		case MessageParser::RepubRemoteBroadcastPublisher:
			repubRemoteBroadcastPublisher( user, identity,
					friendClaim, mp.messageId, mp.distName, mp.generation, mp.body );
			break;
		case MessageParser::RepubRemoteBroadcastAuthor: 
			repubRemoteBroadcastAuthor( user, identity, friendClaim,
					mp.iduri, mp.messageId, mp.distName, mp.generation, mp.body );
			break;
		case MessageParser::RepubRemoteBroadcastSubject: 
			repubRemoteBroadcastSubject( user, identity, friendClaim,
					mp.iduri, mp.messageId, mp.distName, mp.generation, mp.body );
			break;
		case MessageParser::ReturnRemoteBroadcastAuthor:
			returnRemoteBroadcastAuthor( user, identity, mp.reqid, mp.body );
			break;
		case MessageParser::ReturnRemoteBroadcastSubject:
			returnRemoteBroadcastSubject( user, identity, mp.reqid, mp.body );
			break;
		case MessageParser::BroadcastSuccessAuthor:
			broadcastSuccessAuthor( user, identity, mp.messageId );
			break;
		case MessageParser::BroadcastSuccessSubject:
			broadcastSuccessSubject( user, identity, mp.messageId );
			break;
		case MessageParser::UserMessage:
		default:
			throw NotImplemented();
			break;
	}
}

void Server::receiveMessage( const String &relid, const String &msg )
{
	FriendClaim friendClaim( mysql, relid );

	if ( friendClaim.state == FC_ESTABLISHED ) {
		message( "message for established friend claim\n" );
		receiveMessageEstablished( friendClaim, relid, msg );
	}
	else if ( friendClaim.state == FC_SENT || friendClaim.state == FC_GRANTED_ACCEPT ) {
		message( "message is a prefriend message\n" );
		recieveMessagePrefriend( friendClaim, relid, msg );
	}
	else {
		throw UnexpectedFriendClaimState( friendClaim.state );
	}
}

void Server::receiveFofMessage( const String &relid, const String &msg )
{
	FriendClaim friendClaim( mysql, relid );

	User user( mysql, friendClaim.userId );
	Identity friendId( mysql, friendClaim.identityId );

	/* Decrypt. */
	String decrypted1 = keyAgent.decryptVerify1( user, msg );

	PacketSignedId packetSignedId( decrypted1 );
	Identity senderId( mysql, packetSignedId.iduri );

	fetchPublicKey( senderId );
	String decrypted2 = keyAgent.decryptVerify2( senderId, user, decrypted1 );

	message("FOF message decrypted\n");

	FofMessageParser mp;
	mp.parse( decrypted2 );

	switch ( mp.type ) {
		case FofMessageParser::FetchRbBroadcastKey:
			fetchRbBroadcastKey( user, friendId, friendClaim, senderId,
					mp.distName, mp.generation, mp.memberProof );
			break;
		default:
			throw NotImplemented();
			break;
	}
}

void Server::submitMessage( const String &user, const String &iduri, const String &msg )
{
	/* NOT IMPELEMTED. */
	UserMessageParser msgParser( msg );
	bioWrap.returnOkLocal();
}

