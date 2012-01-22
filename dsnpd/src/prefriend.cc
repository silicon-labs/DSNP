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

void Server::notifyAccept( User &user, Identity &identity, const String &peerNotifyReqid )
{
	/* Verify that there is a friend request. */
	DbQuery checkSentRequest( mysql, 
		"SELECT id "
		"FROM sent_friend_request "
		"WHERE user_id = %L AND identity_id = %L AND peer_notify_reqid = %e ",
		user.id(), identity.id(), peerNotifyReqid() );

	if ( checkSentRequest.rows() != 1 )
		throw FriendRequestInvalid();

	DbQuery( mysql, 
		"UPDATE friend_claim "
		"SET state = %l "
		"WHERE user_id = %L AND identity_id = %L ",
		FC_GRANTED_ACCEPT, user.id(), identity.id()
	);

	bioWrap.returnOkServer();
}

void Server::registered( User &user, Identity &identity, 
		const String &peerNotifyReqid, const String &friendClaimSigKey )
{
	DbQuery reqids( mysql, 
		"SELECT user_notify_reqid "
		"FROM sent_friend_request "
		"WHERE user_id = %L AND identity_id = %L AND peer_notify_reqid = %e",
		user.id(), identity.id(), peerNotifyReqid() );
	
	MYSQL_ROW row = reqids.fetchRow();
	String userNotifyReqid = Pointer( row[0] );

	/* FIXME: use id. */
	DbQuery( mysql, 
		"DELETE FROM sent_friend_request "
		"WHERE user_id = %L AND identity_id = %L AND peer_notify_reqid = %e ",
		user.id(), identity.id(), peerNotifyReqid() );

	DbQuery( mysql, 
		"UPDATE friend_claim "
		"SET state = %l "
		"WHERE user_id = %L AND identity_id = %L ",
		FC_ESTABLISHED, user.id(), identity.id()
	);

	/* Parse the public key. */
	PacketPublicKey epp( friendClaimSigKey );

	FriendClaim friendClaim( mysql, user, identity );
	keyAgent.generateFriendClaimKeys( friendClaim.id );
	keyAgent.storeFriendClaimSigKey( friendClaim.id, friendClaimSigKey );

	String site = user.site();

	notifAgent.notifSentFriendRequestAccepted(
			site, user.iduri, identity.iduri(),
			userNotifyReqid() );

	addToPrimaryNetwork( user, identity );

	String retPacket = keyAgent.signEncrypt( identity, user, keyAgent.pub1 );

	bioWrap.returnOkServer( retPacket );
}

void Server::recieveMessagePrefriend( FriendClaim &friendClaim, const String &relid, const String &msg )
{
	User user( mysql, friendClaim.userId );
	Identity identity( mysql, friendClaim.identityId );

	fetchPublicKey( identity );
	String decrypted = keyAgent.decryptVerify( identity, user, msg );

	PrefriendParser pfp;
	pfp.parse( decrypted );
	switch ( pfp.type ) {
		case PrefriendParser::NotifyAccept:
			notifyAccept( user, identity, pfp.peerNotifyReqid );
			break;
		case PrefriendParser::Registered:
			registered( user, identity, pfp.peerNotifyReqid, pfp.friendClaimSigKey );
			break;
		default:
			break;
	}
}

void Server::acceptFriend( const String &loginToken, const String &acceptReqid )
{
	User user( mysql, User::ByLoginToken(), loginToken );
	if ( user.id() < 0 )
		throw InvalidUser( loginToken );

	/* Find the friend request. */
	DbQuery friendRequest( mysql, 
		"SELECT identity_id, peer_notify_reqid "
		"FROM friend_request "
		"WHERE user_id = %L AND accept_reqid = %e",
		user.id(), acceptReqid() );

	/* Check for a result. */
	if ( friendRequest.rows() == 0 )
		throw FriendRequestInvalid();

	MYSQL_ROW row = friendRequest.fetchRow();
	long long identityId = parseId( row[0] );
	String peerNotifyReqid = Pointer( row[1] );

	Identity identity( mysql, identityId );

	FriendClaim friendClaim( mysql, user, identity );
	if ( friendClaim.state != FC_RECEIVED )
		throw UnexpectedFriendClaimState( friendClaim.state );

	/* Notify the requester. */
	String notifyAccept = consNotifyAccept( peerNotifyReqid );

	/* FIXME: try, catch. */
	String result = sendMessageNow( user, identity.iduri, 
			friendClaim.putRelids[KEY_PRIV3], notifyAccept );

	DbQuery( mysql, 
		"UPDATE friend_claim "
		"SET state = %l "
		"WHERE user_id = %L AND identity_id = %L ",
		FC_ESTABLISHED, user.id(), identity.id()
	);

	keyAgent.generateFriendClaimKeys( friendClaim.id );

	/* Notify the requester. */
	String registered = consRegistered( peerNotifyReqid, keyAgent.pub1 );
	String packet = sendMessageNow( user, identity.iduri(),
			friendClaim.putRelids[KEY_PRIV3], registered );

	String friendClaimSigKey = keyAgent.decryptVerify( identity, user, packet );
	PacketPublicKey epp( friendClaimSigKey );
	
	/* Result will contain the pub key. */
	keyAgent.storeFriendClaimSigKey( friendClaim.id, friendClaimSigKey );

	DbQuery( mysql, 
		"DELETE FROM friend_request WHERE user_id = %L AND accept_reqid = %e",
		user.id(), acceptReqid() );

	String site = user.site();
	notifAgent.notifFriendRequestAccepted( site, user.iduri, 
			identity.iduri(), acceptReqid() );

	addToPrimaryNetwork( user, identity );

	bioWrap.returnOkLocal();
}

