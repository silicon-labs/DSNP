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

void Server::broadcastReceipient( RecipientList &recipients, const String &relid )
{
	recipients.push_back( std::string(relid) );
	bioWrap.returnOkServer();
}

bool Server::haveRbSigKey( const String &rbSigKeyHash )
{
	DbQuery find( mysql,
		"SELECT id FROM rb_key "
		"WHERE hash = %e ",
		rbSigKeyHash() );

	return find.fetchRow() != 0;
}

void Server::queueRbKeyFetch( User &user, FriendClaim &friendClaim, 
		Broadcast &broadcast, const String &identity,
		const String &relid, const String &rbSigKeyHash )
{
	Identity recipient( mysql, identity );

	fetchPublicKey( recipient );
	String enc = keyAgent.signIdEncrypt( recipient, user, user.iduri,
			broadcast.bkId, broadcast.distName, broadcast.generation );

	queueFofMessage( broadcast.bkId, relid, friendClaim, recipient, enc );
}

/* Returns true if we have all the keys necessary to process. False if we need
 * more keys. */
bool Server::verifyBroadcast( User &user, Identity &broadcaster, FriendClaim &friendClaim, Broadcast &b )
{
	bool verified = true;
	UserMessageParser msgParser( b.plainMsg );

	if ( msgParser.publisher != b.publisher )
		throw ParseError( __FILE__, __LINE__ );

	if ( b.publisher.length != 0 ) {
		message( "verifying publisher\n");
		Identity publisherId( mysql, b.publisher );
		fetchPublicKey( publisherId );

		if ( publisherId.id() == broadcaster.id() ) {
			keyAgent.bkDetachedForeignVerify( publisherId, b.bkId,
					b.publisherSig, b.plainMsg );
		}
		else {
			/* Check if we trust the key. */
			PacketDetachedSigKey epp( b.publisherSig );
			message("BROADCAST VERIFY with key %s\n", epp.pubKeyHash() );

			if ( ! haveRbSigKey( epp.pubKeyHash ) ) {
				queueRbKeyFetch( user, friendClaim, b, b.publisher, b.publisherRelid, epp.pubKeyHash );
				verified = false;
			}
			else {
				keyAgent.bkDetachedRepubForeignVerify( publisherId, b.bkId,
						b.publisherSig, b.plainMsg );
			}
		}
	}

	if ( msgParser.author != b.author )
		throw ParseError( __FILE__, __LINE__ );

	if ( b.author.length != 0 ) {
		message( "verifying author\n");
		Identity authorId( mysql, b.author );
		fetchPublicKey( authorId );

		if ( authorId.id() == broadcaster.id() ) {
			keyAgent.bkDetachedForeignVerify( authorId, b.bkId,
					b.authorSig, b.plainMsg );
		}
		else {
			/* Check if we trust the key. */
			PacketDetachedSigKey epp( b.authorSig );
			message("BROADCAST VERIFY with key %s\n", epp.pubKeyHash() );

			if ( ! haveRbSigKey( epp.pubKeyHash ) ) {
				queueRbKeyFetch( user, friendClaim, b, b.author, b.authorRelid, epp.pubKeyHash );
				verified = false;
			}
			else {
				keyAgent.bkDetachedRepubForeignVerify( authorId, b.bkId,
						b.authorSig, b.plainMsg );
			}
		}
	}

	if ( (long)msgParser.subjects.size() != b.subjectList.length() )
		throw ParseError( __FILE__, __LINE__ );

	SubjectList::iterator ms = msgParser.subjects.begin();
	for ( BroadcastSubject *bs = b.subjectList.head;
			bs != 0; bs = bs->next, ms++ )
	{
		message( "verifying subject\n");
		String mss = Pointer( ms->c_str() );
		if ( mss != bs->subject )
			throw ParseError( __FILE__, __LINE__ );

		Identity subjectId( mysql, bs->subject );
		fetchPublicKey( subjectId );

		if ( subjectId.id() == broadcaster.id() ) {
			keyAgent.bkDetachedForeignVerify( subjectId, b.bkId,
					bs->subjectSig, b.plainMsg );
		}
		else {
			/* Check if we trust the key. */
			PacketDetachedSigKey epp( bs->subjectSig );
			message("BROADCAST VERIFY with key %s\n", epp.pubKeyHash() );

			if ( ! haveRbSigKey( epp.pubKeyHash ) ) {
				queueRbKeyFetch( user, friendClaim, b, bs->subject, bs->subjectRelid, epp.pubKeyHash );
				verified = false;
			}
			else {
				keyAgent.bkDetachedRepubForeignVerify( subjectId, b.bkId,
						bs->subjectSig, b.plainMsg );
			}
		}
	}

	if ( verified && b.publisher.length > 0 ) {
		message( "broadcast content: notifying \n" );
		String site = user.site();
		notifAgent.notifBroadcast( site, user.iduri, broadcaster.iduri, b.plainMsg );
	}

	return verified;
}

void Server::receiveBroadcast( const String &relid,
		const String &distName, long long keyGen, const String &msg )
{
	FriendClaim friendClaim( mysql, relid );
	User user( mysql, friendClaim.userId );
	Identity broadcaster( mysql, friendClaim.identityId );

	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT get_broadcast_key.id "
		"FROM get_broadcast_key "
		"WHERE friend_claim_id = %L AND "
		"	network_dist = %e AND generation = %L ",
		friendClaim.id, distName(), keyGen );

	if ( recipient.rows() == 0 )
		throw BroadcastRecipientInvalid();

	MYSQL_ROW row = recipient.fetchRow();
	long long bkId = parseId( row[0] );

	/* Do the decryption. */
	fetchPublicKey( broadcaster );
	String decrypted = keyAgent.bkDecrypt( bkId, msg );

	/* May build this up. */
	Broadcast b;
	b.bkId = bkId;
	b.distName = distName;
	b.generation = keyGen;
	b.user = user.iduri;

	PacketBroadcast epp( b, decrypted );

	bool processed = verifyBroadcast( user, broadcaster, friendClaim, b );
	if ( !processed ) {
		message("DELAYING BROADCAST, NO KEYS\n");

		DbQuery( mysql,
			"INSERT INTO received_broadcast "
			"( reprocess, process_after, relid, dist_name, generation, message ) "
			"VALUES ( false, DATE_ADD( NOW(), INTERVAL 5 SECOND ), %e, %e, %L, %d ) ",
			relid(), distName(), keyGen, msg.binary(), msg.length );
	}
}

void Server::receiveBroadcastList( RecipientList &recipients, const String &distName,
		long long keyGen, const String &msg )
{
	for ( RecipientList::iterator r = recipients.begin(); r != recipients.end(); r++ ) {
		String relid = Pointer( r->c_str() );
		receiveBroadcast( relid, distName, keyGen, msg );
	}

	bioWrap.returnOkServer();
}

void Server::submitBroadcast( const String &loginToken, const String &msg )
{
	/* Verify the message. */
	UserMessageParser msgParser( msg );

	User user( mysql, User::ByLoginToken(), loginToken );

	/* Get the latest put session key. */
	long long networkId = findPrimaryNetworkId( mysql, user );
	PutKey put( mysql, networkId );
	String encPacket = keyAgent.bkDetachedSign( user, put.id, msg ); 

	Broadcast broadcast;
	broadcast.plainMsg = msg;

	broadcast.publisher = user.iduri;
	broadcast.publisherSig = encPacket;
	/*broadcast.publisherRelid = Pointer("x");*/

	String command = consBroadcast( broadcast );
	queueBroadcast( user, command );
	bioWrap.returnOkLocal();
}

void Server::verifyRemoteBroadcast( Identity &publisherId, Identity &authorId, 
		UserMessageParser &msgParser )
{
	/* Make sure the actors specified now match the actors in the message. */
	if ( publisherId.iduri != msgParser.publisher )
		throw ParseError( __FILE__, __LINE__ );
	if ( authorId.iduri != msgParser.author )
		throw ParseError( __FILE__, __LINE__ );
}

Allocated Server::createRbRequestActor( long long remoteBroadcastRequestId,
		int state, int type, long long identityId )
{
	u_char reqidBin[REQID_SIZE];
	RAND_bytes( reqidBin, REQID_SIZE );
	String reqid = binToBase64( reqidBin, REQID_SIZE );

	DbQuery( mysql, 
		"INSERT INTO rb_request_actor "
		"( "
		"	remote_broadcast_request_id, state, "
		"	actor_type, identity_id, return_reqid "
		") "
		"VALUES ( %L, %l, %l, %L, %e )",
		remoteBroadcastRequestId, state, type,
		identityId, reqid() );

	return reqid.relinquish();
}

void Server::remoteBroadcastRequest( const String &floginToken, const String &plainMsg )
{
	/* Get the current time. */
	String time = timeNow();

	/* Verify the message. */
	UserMessageParser msgParser( plainMsg );
	ReqidList reqidList;

	FriendClaim friendClaim( mysql, FriendClaim::ByFloginToken(), floginToken );

	User user( mysql, friendClaim.userId );
	String publisher = user.iduri;
	Identity publisherId( mysql, publisher );
	Identity authorId( mysql, friendClaim.identityId );

	/* Check the message. */
	verifyRemoteBroadcast( publisherId, authorId, msgParser );

	//returned_reqid_parser( mysql, to_user, result );
	String authorHash = makeIduriHash( authorId.iduri );

	/*
	 * Store the remote broadcast request
	 */
	DbQuery( mysql,
		"INSERT INTO remote_broadcast_request "
		"( user_id, identity_id, state, message_id, plain_message ) "
		"VALUES ( %L, %L, %l, %e, %d )",
		user.id(), authorId.id(), RB_REQ_STATE_PENDING, 
		msgParser.messageId(), plainMsg.binary(), plainMsg.length );
	
	long long remoteBroadcastRequestId = lastInsertId( mysql );

	/* Start with complete. Eventually we will need to grant an opportunity to
	 * authorize. */
	String publisherReturnReqid = createRbRequestActor( 
			remoteBroadcastRequestId, ACTOR_STATE_COMPLETE, 
			ACTOR_TYPE_PUBLISHER, authorId.id() );

	String authorReturnReqid = createRbRequestActor( 
			remoteBroadcastRequestId, ACTOR_STATE_PENDING, 
			ACTOR_TYPE_AUTHOR, authorId.id() );

	for ( SubjectList::const_iterator s = msgParser.subjects.begin(); 
			s != msgParser.subjects.end(); s++ )
	{
		Identity subject( mysql, s->c_str() );
		String subjectReturnReqid = createRbRequestActor( 
				remoteBroadcastRequestId, ACTOR_STATE_PENDING,
				ACTOR_TYPE_SUBJECT, subject.id() );

		reqidList.push_back( string(subjectReturnReqid()) );
	}

	/*
	 * Initiate authorization with the author.
	 */

	/* Find current generation and youngest broadcast key */
	long long networkId = findPrimaryNetworkId( mysql, user );
	PutKey put( mysql, networkId );

	/*
	 * Recipients.
	 */
	DbQuery rec( mysql,
		"SELECT identity.id, identity.iduri, put_relid.put_relid "
		"FROM friend_claim "
		"JOIN put_relid ON friend_claim.id = put_relid.friend_claim_id "
		"JOIN identity ON friend_claim.identity_id = identity.id "
		"JOIN network_member "
		"ON friend_claim.id = network_member.friend_claim_id "
		"WHERE friend_claim.user_id = %L AND friend_claim.state = %l AND"
		"	network_member.network_id = %L AND put_relid.key_priv = %l",
		user.id(), FC_ESTABLISHED, networkId, KEY_PRIV4 );

	RecipientList2 recipientList;
	while ( true ) {
		MYSQL_ROW row = rec.fetchRow();
		if ( !row )
			break;
		u_long *lengths = rec.fetchLengths();
		
		Recipient *r = new Recipient;
		r->relid = Pointer( row[2], lengths[2] );
		r->iduri = Pointer( row[1], lengths[1] );
		recipientList.append( r );
	}
	String recipients = consRecipientList( recipientList );

	String remotePublishCmd = consEncryptRemoteBroadcastAuthor( 	
			authorReturnReqid, floginToken, put.distName,
			put.generation, recipients, plainMsg );

	String result = sendMessageNow( user, authorId.iduri,
			friendClaim.putRelids[KEY_PRIV3](), remotePublishCmd );
	
	if ( result.length > 0 )
		throw ParseError( __FILE__, __LINE__ );
	
	DbQuery( mysql,
		"UPDATE remote_broadcast_request "
		"SET author_reqid = %e WHERE id = %L ",
		result(), remoteBroadcastRequestId );
	
	/*
	 * Authorize with the subjects.
	 */

	ReqidList::const_iterator r = reqidList.begin();
	for ( SubjectList::const_iterator s = msgParser.subjects.begin(); 
			s != msgParser.subjects.end(); s++, r++ )
	{
		Identity subject( mysql, s->c_str() );
		FriendClaim subjectFriendClaim( mysql, user, subject );

		String reqid = Pointer( r->c_str() );
		String encryptSubjectCmd = consEncryptRemoteBroadcastSubject(
				reqid, authorHash, put.distName,
				put.generation, recipients, plainMsg );

		String result = sendMessageNow( user, subject.iduri,
				subjectFriendClaim.putRelids[KEY_PRIV3](),
				encryptSubjectCmd );

		if ( result.length > 0 )
			throw ParseError( __FILE__, __LINE__ );
	}

	bioWrap.returnOkLocal( authorReturnReqid );
}

void Server::encryptRemoteBroadcastAuthor( User &user, Identity &publisherId,
		FriendClaim &friendClaim, const String &returnReqid, const String &token,
		const String &network, long long generation, const String &recipients,
		const String &plainMsg )
{
	DbQuery flogin( mysql,
		"SELECT id FROM remote_flogin_token "
		"WHERE user_id = %L AND identity_id = %L AND login_token = %e",
		user.id(), publisherId.id(), token() );

	if ( flogin.rows() == 0 )
		throw LoginTokenNotValid();

	String userIduri = user.iduri;
	Identity authorId( mysql, userIduri );

	/* Verify the message. */
	UserMessageParser msgParser( plainMsg );
	PacketRecipientList epp( recipients );

	/* Check the message. */
	verifyRemoteBroadcast( publisherId, authorId, msgParser );

	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT get_broadcast_key.id "
		"FROM get_broadcast_key "
		"WHERE friend_claim_id = %L AND "
		"	network_dist = %e AND generation = %L ",
		friendClaim.id, network(), generation );

	if ( recipient.rows() == 0 )
		throw BroadcastRecipientInvalid();

	MYSQL_ROW row = recipient.fetchRow();
	long long bkId = parseId( row[0] );

	FriendClaim pubFriendClaim( mysql, user, publisherId );
	String encPacket = keyAgent.bkDetachedRepubForeignSign( user,
			pubFriendClaim.id, bkId, plainMsg );

	DbQuery( mysql,
		"INSERT INTO remote_broadcast_response "
		"	( user_id, publisher_id, state, return_reqid, "
		"		message_id, plain_message, enc_message ) "
		"VALUES ( %L, %L, %l, %e, %e, %d, %d )",
		user.id(), publisherId.id(), RB_RSP_STATE_PENDING,
		returnReqid(), msgParser.messageId(),
		plainMsg.binary(), plainMsg.length,
		encPacket.binary(), encPacket.length );

	long long remoteBroadcastResponseId = lastInsertId( mysql );

	/*
	 * Store the actors
	 */
	DbQuery( mysql, 
		"INSERT INTO rb_response_actor "
		"( remote_broadcast_response_id, actor_type, identity_id ) "
		"VALUES ( %L, %l, %L )",
		remoteBroadcastResponseId, ACTOR_TYPE_PUBLISHER, publisherId.id() );

	DbQuery( mysql, 
		"INSERT INTO rb_response_actor "
		"( remote_broadcast_response_id, actor_type, identity_id ) "
		"VALUES ( %L, %l, %L )",
		remoteBroadcastResponseId, ACTOR_TYPE_AUTHOR, authorId.id() );

	for ( SubjectList::const_iterator s = msgParser.subjects.begin(); 
			s != msgParser.subjects.end(); s++ )
	{
		Identity subject( mysql, s->c_str() );
		DbQuery( mysql, 
			"INSERT INTO rb_response_actor "
			"( remote_broadcast_response_id, actor_type, identity_id ) "
			"VALUES ( %L, %l, %L )",
			remoteBroadcastResponseId, ACTOR_TYPE_SUBJECT, subject.id() );
	}

	bioWrap.returnOkServer();
}

void Server::encryptRemoteBroadcastSubject( User &user, Identity &publisherId,
		FriendClaim &friendClaim, const String &returnReqid, const String &authorHash,
		const String &network, long long generation, const String &recipients,
		const String &plainMsg )
{
	/* Find the friend claim by the hash. */
	Identity authorId( mysql, Identity::ByHash(), authorHash );

	message("encrypt remote broadcast subject: publisher is: %s author is: %s\n", 
			publisherId.iduri(), authorId.iduri());

	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT get_broadcast_key.id "
		"FROM get_broadcast_key "
		"WHERE friend_claim_id = %L AND "
		"	network_dist = %e AND generation = %L ",
		friendClaim.id, network(), generation );

	if ( recipient.rows() == 0 )
		throw BroadcastRecipientInvalid();

	/* Parse the message. */
	UserMessageParser msgParser( plainMsg );
	PacketRecipientList epp( recipients );

	String userIduri = user.iduri;
	Identity subjectId( mysql, userIduri );

	/* Check the message. */
	verifyRemoteBroadcast( publisherId, authorId, msgParser );

	MYSQL_ROW row = recipient.fetchRow();
	long long bkId = parseId( row[0] );

	FriendClaim pubFriendClaim( mysql, user, publisherId );
	String encPacket = keyAgent.bkDetachedRepubForeignSign( user,
			pubFriendClaim.id, bkId, plainMsg );

	String returnCmd = consReturnRemoteBroadcastSubject(
			returnReqid, encPacket );

	String result = sendMessageNow( user, publisherId.iduri(),
			friendClaim.putRelids[KEY_PRIV3](), returnCmd );

	if ( result() == 0 )
		throw ParseError( __FILE__, __LINE__ );

	DbQuery( mysql,
		"INSERT INTO remote_broadcast_subject "
		"	( user_id, publisher_id, state, return_reqid, "
		"		message_id, plain_message, enc_message ) "
		"VALUES ( %L, %L, %l, %e, %e, %d, %d )",
		user.id(), publisherId.id(), RB_RSP_STATE_PENDING,
		returnReqid(), msgParser.messageId(),
		plainMsg.binary(), plainMsg.length,
		encPacket.binary(), encPacket.length );

	long long remoteBroadcastResponseId = lastInsertId( mysql );

	/*
	 * Store the actors
	 */
	DbQuery( mysql, 
		"INSERT INTO rb_subject_actor "
		"( remote_broadcast_subject_id, actor_type, identity_id ) "
		"VALUES ( %L, %l, %L )",
		remoteBroadcastResponseId, ACTOR_TYPE_PUBLISHER, publisherId.id() );

	DbQuery( mysql, 
		"INSERT INTO rb_subject_actor "
		"( remote_broadcast_subject_id, actor_type, identity_id ) "
		"VALUES ( %L, %l, %L )",
		remoteBroadcastResponseId, ACTOR_TYPE_AUTHOR, authorId.id() );

	for ( SubjectList::const_iterator s = msgParser.subjects.begin(); 
			s != msgParser.subjects.end(); s++ )
	{
		Identity subject( mysql, s->c_str() );
		DbQuery( mysql, 
			"INSERT INTO rb_subject_actor "
			"( remote_broadcast_subject_id, actor_type, identity_id ) "
			"VALUES ( %L, %l, %L )",
			remoteBroadcastResponseId, ACTOR_TYPE_SUBJECT, subject.id() );
	}

	/* Just send the message back as it is for now. */
	bioWrap.returnOkServer();
}

void Server::returnRemoteBroadcastAuthor( User &user, Identity &identity,
		const String &reqid, const String &msg )
{
	DbQuery recipient( mysql, 
		"UPDATE rb_request_actor "
		"SET state = %l, enc_message = %d "
		"WHERE return_reqid = %e ",
		ACTOR_STATE_RETURNED,
		msg.binary(), msg.length, 
		reqid() );

	DbQuery rbrId( mysql, 
		"SELECT remote_broadcast_request_id "
		"FROM rb_request_actor "
		"WHERE return_reqid = %e ",
		reqid() );

	MYSQL_ROW row = rbrId.fetchRow();
	long long remoteBroadcastRequestId = parseId( row[0] );
	
	checkRemoteBroadcastComplete( user, remoteBroadcastRequestId );
	
	bioWrap.returnOkServer( reqid );
}

void Server::returnRemoteBroadcastSubject( User &user, Identity &identity,
		const String &reqid, const String &msg )
{
	DbQuery recipient( mysql, 
		"UPDATE rb_request_actor "
		"SET state = %l, enc_message = %d "
		"WHERE return_reqid = %e ",
		ACTOR_STATE_COMPLETE, 
		msg.binary(), msg.length, reqid() );

	DbQuery rbrId( mysql, 
		"SELECT remote_broadcast_request_id "
		"FROM rb_request_actor "
		"WHERE return_reqid = %e ",
		reqid() );

	MYSQL_ROW row = rbrId.fetchRow();
	long long remoteBroadcastRequestId = parseId( row[0] );
	
	checkRemoteBroadcastComplete( user, remoteBroadcastRequestId );

	bioWrap.returnOkServer( reqid );
}

void Server::remoteBroadcastResponse( const String &loginToken, const String &reqid )
{
	User user( mysql, User::ByLoginToken(), loginToken );

	DbQuery recipient( mysql, 
		"SELECT publisher_id, enc_message "
		"FROM remote_broadcast_response "
		"WHERE user_id = %L AND return_reqid = %e",
		user.id(), reqid() );
	
	if ( recipient.rows() == 0 )
		throw RequestIdInvalid();

	MYSQL_ROW row = recipient.fetchRow();
	u_long *lengths = recipient.fetchLengths();
	long long publisherId = parseId( row[0] );
	String encMessage = Pointer( row[1], lengths[1] );
	message( "flushing remote with reqid: %s\n", reqid() );

	Identity publisher( mysql, publisherId );
	FriendClaim friendClaim( mysql, user, publisher );

	String returnCmd = consReturnRemoteBroadcastAuthor(
			reqid, encMessage );

	String result = sendMessageNow( user,
			publisher.iduri(),
			friendClaim.putRelids[KEY_PRIV3](),
			returnCmd );

	if ( result() == 0 )
		throw ParseError( __FILE__, __LINE__ );

	bioWrap.returnOkLocal( result );
}

void Server::broadcastSuccessAuthor( User &user, Identity &publisherId, const String &messageId )
{
	message("looking for %lld %lld %s\n", user.id(), publisherId.id(), messageId() );

	DbQuery findResponse( mysql,
		"SELECT id, plain_message "
		"FROM remote_broadcast_response "
		"WHERE user_id = %L AND publisher_id = %L AND message_id = %e ", 
		user.id(), publisherId.id(), messageId() );
	
	if ( findResponse.rows() != 1 )
		throw InvalidRemoteBroadcastResponse();

	MYSQL_ROW row = findResponse.fetchRow();
	u_long *lengths = findResponse.fetchLengths();

	long long remoteBroadcastResponseId = parseId( row[0] );
	String plainMsg = Pointer( row[1], lengths[1] );

	/* Notifiy the user agent. */
	String site = user.site();
	notifAgent.notifBroadcast( site, user.iduri,
			publisherId.iduri(), plainMsg );

	Broadcast broadcast;
	broadcast.plainMsg = plainMsg;

	/* Find current generation and youngest broadcast key */
	long long networkId = findPrimaryNetworkId( mysql, user );
	PutKey put( mysql, networkId );
	String encPacket = keyAgent.bkDetachedSign( user, put.id, plainMsg ); 

	broadcast.author = user.iduri;
	broadcast.authorSig = encPacket;
	/*broadcast.authorRelid = Pointer("x");*/

	/*
	 * Recipients.
	 */
	DbQuery rec( mysql,
		"SELECT identity.id, identity.iduri, put_relid.put_relid "
		"FROM friend_claim "
		"JOIN put_relid ON friend_claim.id = put_relid.friend_claim_id "
		"JOIN identity ON friend_claim.identity_id = identity.id "
		"JOIN network_member "
		"ON friend_claim.id = network_member.friend_claim_id "
		"WHERE friend_claim.user_id = %L AND friend_claim.state = %l AND"
		"	network_member.network_id = %L AND put_relid.key_priv = %l",
		user.id(), FC_ESTABLISHED, networkId, KEY_PRIV3 );

	RecipientList2 recipientList;
	while ( true ) {
		MYSQL_ROW row = rec.fetchRow();
		if ( !row )
			break;
		u_long *lengths = rec.fetchLengths();
		
		Recipient *r = new Recipient;
		r->relid = Pointer( row[2], lengths[2] );
		r->iduri = Pointer( row[1], lengths[1] );
		recipientList.append( r );
	}
	String recipients = consRecipientList( recipientList );


	/* 
	 * Publish the message.
	 */
	DbQuery actors( mysql,
		"SELECT actor_type, identity_id "
		"FROM rb_response_actor "
		"WHERE remote_broadcast_response_id = %L ",
		remoteBroadcastResponseId );

	while ( ( row = actors.fetchRow() ) != 0 ) {
		lengths = actors.fetchLengths();
		int actorType = atoi( row[0] );
		long long identityId = parseId( row[1] );

		Identity identity( mysql, identityId );

		if ( actorType == ACTOR_TYPE_PUBLISHER ) {
			message("finding publisher friend claim: %lld identity: %lld\n",
					user.id(), identityId );

			FriendClaim friendClaim( mysql, user, identity );

			String repub = consRepubRemoteBroadcastPublisher(
					messageId, put.distName, put.generation, recipients );

			String result = sendMessageNow( user, identity.iduri,
					friendClaim.putRelids[KEY_PRIV3](), repub );

			if ( result.length == 0 )
				throw ParseError( __FILE__, __LINE__ );

			broadcast.publisher = identity.iduri;
			broadcast.publisherSig = result;
			broadcast.publisherRelid = friendClaim.putRelids[KEY_PRIV3];
		}
		else if ( actorType == ACTOR_TYPE_AUTHOR ) {
			/* SELF */
		}
		else if ( actorType == ACTOR_TYPE_SUBJECT ) { 
			message("finding subject friend claim: %lld identity: %lld\n",
					user.id(), identityId );
			FriendClaim friendClaim( mysql, user, identity );

			String repub = consRepubRemoteBroadcastSubject(
					publisherId.iduri, messageId, put.distName,
					put.generation, recipients );

			String result = sendMessageNow( user, identity.iduri,
					friendClaim.putRelids[KEY_PRIV3](),
					repub );

			BroadcastSubject *bs = new BroadcastSubject;
			bs->subject = identity.iduri;
			bs->subjectSig = result;
			bs->subjectRelid = friendClaim.putRelids[KEY_PRIV3];
			broadcast.subjectList.append( bs );
		}
	}

	String command = consBroadcast( broadcast );
	queueBroadcast( user, command );

	/*
	 * Clear the response data from the database.
	 */
//	DbQuery( mysql, 
//		"DELETE FROM remote_broadcast_response "
//		"WHERE id = %L",
//		remoteBroadcastResponseId );
//
//	DbQuery( mysql, 
//		"DELETE FROM rb_response_actor "
//		"WHERE remote_broadcast_response_id = %L",
//		remoteBroadcastResponseId );

	bioWrap.returnOkServer();
}

void Server::broadcastSuccessSubject( User &user, Identity &publisherId, const String &messageId )
{
	message("looking for %lld %lld %s\n", user.id(), publisherId.id(), messageId() );

	DbQuery findResponse( mysql,
		"SELECT id, plain_message "
		"FROM remote_broadcast_subject "
		"WHERE user_id = %L AND publisher_id = %L AND message_id = %e ", 
		user.id(), publisherId.id(), messageId() );

	if ( findResponse.rows() != 1 )
		throw InvalidRemoteBroadcastResponse();

	MYSQL_ROW row = findResponse.fetchRow();
	u_long *lengths = findResponse.fetchLengths();

	long long remoteBroadcastResponseId = parseId( row[0] );
	String plainMsg = Pointer( row[1], lengths[1] );

	/* Notifiy the user agent. */
	String site = user.site();
	notifAgent.notifBroadcast( site, user.iduri,
			publisherId.iduri(), plainMsg );

	Broadcast broadcast;
	broadcast.plainMsg = plainMsg;

	/* Find current generation and youngest broadcast key */
	long long networkId = findPrimaryNetworkId( mysql, user );
	PutKey put( mysql, networkId );
	String encPacket = keyAgent.bkDetachedSign( user, put.id, plainMsg ); 

	BroadcastSubject *bs = new BroadcastSubject;
	String userIduri = user.iduri;

	bs->subject = userIduri;
	bs->subjectSig = encPacket;
	/*bs->subjectRelid = Pointer("x");*/
	broadcast.subjectList.append( bs );

	/*
	 * Recipients.
	 */
	DbQuery rec( mysql,
		"SELECT identity.id, identity.iduri, put_relid.put_relid "
		"FROM friend_claim "
		"JOIN put_relid ON friend_claim.id = put_relid.friend_claim_id "
		"JOIN identity ON friend_claim.identity_id = identity.id "
		"JOIN network_member "
		"ON friend_claim.id = network_member.friend_claim_id "
		"WHERE friend_claim.user_id = %L AND friend_claim.state = %l AND"
		"	network_member.network_id = %L AND put_relid.key_priv = %l",
		user.id(), FC_ESTABLISHED, networkId, KEY_PRIV3 );

	RecipientList2 recipientList;
	while ( true ) {
		MYSQL_ROW row = rec.fetchRow();
		if ( !row )
			break;
		u_long *lengths = rec.fetchLengths();
		
		Recipient *r = new Recipient;
		r->relid = Pointer( row[2], lengths[2] );
		r->iduri = Pointer( row[1], lengths[1] );
		recipientList.append( r );
	}
	String recipients = consRecipientList( recipientList );

	/* 
	 * Publish the message.
	 */
	DbQuery actors( mysql,
		"SELECT actor_type, identity_id "
		"FROM rb_subject_actor "
		"WHERE remote_broadcast_subject_id = %L ",
		remoteBroadcastResponseId );

	while ( ( row = actors.fetchRow() ) != 0 ) {
		lengths = actors.fetchLengths();
		int actorType = atoi( row[0] );
		long long identityId = parseId( row[1] );

		Identity identity( mysql, identityId );

		if ( actorType == ACTOR_TYPE_PUBLISHER ) {
			message("finding publisher friend claim: %lld identity: %lld\n",
					user.id(), identityId );

			FriendClaim friendClaim( mysql, user, identity );

			String repub = consRepubRemoteBroadcastPublisher(
					messageId, put.distName, put.generation, recipients );
			
			String result = sendMessageNow( user, identity.iduri,
					friendClaim.putRelids[KEY_PRIV3](),
					repub );

			if ( result.length == 0 )
				throw ParseError( __FILE__, __LINE__ );

			broadcast.publisher = identity.iduri;
			broadcast.publisherSig = result;
			broadcast.publisherRelid = friendClaim.putRelids[KEY_PRIV3];
		}
		else if ( actorType == ACTOR_TYPE_AUTHOR ) {
			message("finding author friend claim: %lld identity: %lld\n",
					user.id(), identityId );

			FriendClaim friendClaim( mysql, user, identity );

			String repub = consRepubRemoteBroadcastAuthor(
					publisherId.iduri, messageId,
					put.distName, put.generation, recipients );

			String result = sendMessageNow( user, identity.iduri,
					friendClaim.putRelids[KEY_PRIV3](),
					repub );

			if ( result.length == 0 )
				throw ParseError( __FILE__, __LINE__ );

			broadcast.author = identity.iduri;
			broadcast.authorSig = result;
			broadcast.authorRelid = friendClaim.putRelids[KEY_PRIV3];
		}
		else if ( actorType == ACTOR_TYPE_SUBJECT ) { 
			/* Exclude ourselves. */
			if ( identity.iduri != userIduri ) {
				message("finding subject friend claim: %lld identity: %lld\n",
						user.id(), identityId );
				FriendClaim friendClaim( mysql, user, identity );

				String repub = consRepubRemoteBroadcastSubject(
						publisherId.iduri, messageId, put.distName,
						put.generation, recipients );

				String result = sendMessageNow( user, identity.iduri,
						friendClaim.putRelids[KEY_PRIV3](),
						repub );

				BroadcastSubject *bs = new BroadcastSubject;
				bs->subject = identity.iduri;
				bs->subjectSig = result;
				bs->subjectRelid = friendClaim.putRelids[KEY_PRIV3];
				broadcast.subjectList.append( bs );
			}
		}
	}

	String command = consBroadcast( broadcast );
	queueBroadcast( user, command );

	/*
	 * Clear the response data from the database.
	 */
//	DbQuery( mysql, 
//		"DELETE FROM remote_broadcast_subject "
//		"WHERE id = %L",
//		remoteBroadcastResponseId );
//
//	DbQuery( mysql, 
//		"DELETE FROM rb_subject_actor "
//		"WHERE remote_broadcast_subject_id = %L",
//		remoteBroadcastResponseId );

	bioWrap.returnOkServer();
}

void Server::checkRemoteBroadcastComplete( User &user, long long remoteBroadcastRequestId )
{
	message("checking if remote_broadcast_request %lld has completed\n", 
		remoteBroadcastRequestId );

	/* Look for non-complete actors. */
	DbQuery actorCheck( mysql, 
		"SELECT id "
		"FROM rb_request_actor "
		"WHERE remote_broadcast_request_id = %L AND "
		"	state != %l ",
		remoteBroadcastRequestId, 
		ACTOR_STATE_COMPLETE );

	if ( actorCheck.rows() > 0 ) {
		message("  ... not done\n" );
		return;
	}

	message( "  ... done \n" );

	DbQuery recipient( mysql, 
		"SELECT "
		"	message_id, plain_message, enc_message "
		"FROM remote_broadcast_request "
		"WHERE id = %L ",
		remoteBroadcastRequestId );
	
	if ( recipient.rows() != 1 )
		throw InvalidRemoteBroadcastRequest();

	MYSQL_ROW row = recipient.fetchRow();
	u_long *lengths = recipient.fetchLengths();

	String messageId = Pointer( row[0], lengths[0] );
	String plainMsg = Pointer( row[1], lengths[1] );

	/* 
	 * The actors.
	 */
	DbQuery actors( mysql,
		"SELECT actor_type, identity_id, enc_message "
		"FROM rb_request_actor "
		"WHERE remote_broadcast_request_id = %L ",
		remoteBroadcastRequestId );

	Broadcast broadcast;
	broadcast.plainMsg = plainMsg;

	/* Get the latest put session key. */
	long long networkId = findPrimaryNetworkId( mysql, user );
	PutKey put( mysql, networkId );
	String encPacket = keyAgent.bkDetachedSign( user, put.id, plainMsg ); 

	broadcast.publisher = user.iduri;
	broadcast.publisherSig = encPacket;
	/*broadcast.publisherRelid = Pointer("x");*/

	while ( ( row = actors.fetchRow() ) != 0 ) {
		lengths = actors.fetchLengths();
		int actorType = atoi( row[0] );
		long long identityId = parseId( row[1] );
		String actorEncMessage = Pointer( row[2], lengths[2] );

		Identity identity( mysql, identityId );
		FriendClaim friendClaim( mysql, user, identity );

		if ( actorType == ACTOR_TYPE_AUTHOR ) {
			String successMessage = consBroadcastSuccessAuthor( messageId );
			
			queueMessage( user, identity.iduri,
				friendClaim.putRelids[KEY_PRIV3],
				successMessage );

			broadcast.author = identity.iduri;
			broadcast.authorSig = actorEncMessage;
			broadcast.authorRelid = friendClaim.putRelids[KEY_PRIV3];
		}
		else if ( actorType == ACTOR_TYPE_SUBJECT ) { 
			String successMessage = consBroadcastSuccessSubject( messageId );

			queueMessage( user, identity.iduri,
				friendClaim.putRelids[KEY_PRIV3],
				successMessage );

			BroadcastSubject *bs = new BroadcastSubject;
			bs->subject = identity.iduri;
			bs->subjectSig = actorEncMessage;
			bs->subjectRelid = friendClaim.putRelids[KEY_PRIV3];
			broadcast.subjectList.append( bs );
		}
	}

	String command = consBroadcast( broadcast );
	queueBroadcast( user, command );

	/*
	 * Clear the remote broadcast request data.
	 */
//	DbQuery( mysql, 
//		"DELETE FROM remote_broadcast_request "
//		"WHERE id = %L",
//		remoteBroadcastRequestId );
//
//	DbQuery( mysql, 
//		"DELETE FROM rb_request_actor "
//		"WHERE remote_broadcast_request_id = %L",
//		remoteBroadcastRequestId );
}

void Server::remoteBroadcastFinal( const String &floginToken, const String &reqid )
{
	FriendClaim friendClaim( mysql, FriendClaim::ByFloginToken(), floginToken );
	User user( mysql, friendClaim.userId );

	/* Find current generation and youngest broadcast key. We should probably
	 * store in the db what we've used. Works for now. */
	long long networkId = findPrimaryNetworkId( mysql, user );
	PutKey put( mysql, networkId );

	DbQuery recipient( mysql, 
		"SELECT "
		"	remote_broadcast_request.id, "
		"	remote_broadcast_request.message_id, "
		"	remote_broadcast_request.plain_message, "
		"	rb_request_actor.identity_id, "
		"	rb_request_actor.enc_message "
		"FROM remote_broadcast_request "
		"JOIN rb_request_actor ON "
		"	remote_broadcast_request.id = rb_request_actor.remote_broadcast_request_id "
		"WHERE user_id = %L AND return_reqid = %e",
		user.id(), reqid() );
	
	if ( recipient.rows() != 1 )
		throw InvalidRemoteBroadcastRequest();

	MYSQL_ROW row = recipient.fetchRow();
	u_long *lengths = recipient.fetchLengths();

	long long remoteBroadcastRequestId = parseId( row[0] );
	String messageId = Pointer( row[1], lengths[1] );
	String plainMsg = Pointer( row[2], lengths[2] );
	long long identityId = parseId( row[3] );
	String encMessage = Pointer( row[4], lengths[4] );

	Identity authorId( mysql, identityId );
	String authorHash = makeIduriHash( authorId.iduri );

	DbQuery( mysql,
		"UPDATE rb_request_actor "
		"SET state = %l "
		"WHERE remote_broadcast_request_id = %L AND actor_type = %l",
		ACTOR_STATE_COMPLETE, 
		remoteBroadcastRequestId, 
		ACTOR_TYPE_AUTHOR );
	
	checkRemoteBroadcastComplete( user, remoteBroadcastRequestId );

	bioWrap.returnOkLocal();
}

void Server::repubRemoteBroadcastPublisher( User &user, Identity &actorId,
		FriendClaim &friendClaim, const String &messageId,
		const String &network, long long generation, const String &recipients )
{
	DbQuery find( mysql,
		"SELECT plain_message FROM remote_broadcast_request "
		"WHERE user_id = %L AND message_id = %e ",
		user.id(), messageId()
	);

	if ( find.rows() != 1 )
		throw InvalidRemoteBroadcastRequest();

	MYSQL_ROW row = find.fetchRow();
	u_long *lengths = find.fetchLengths();
	String plainMsg = Pointer( row[0], lengths[0] );

	FriendClaim actorFriendClaim( mysql, user, actorId );

	String userIduri = user.iduri;
	Identity publisherId( mysql, userIduri );

	PacketRecipientList epp( recipients );

	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT get_broadcast_key.id "
		"FROM get_broadcast_key "
		"WHERE friend_claim_id = %L AND "
		"	network_dist = %e AND generation = %L ",
		friendClaim.id, network(), generation );

	if ( recipient.rows() == 0 )
		throw BroadcastRecipientInvalid();

	row = recipient.fetchRow();
	long long bkId = parseId( row[0] );

	String encPacket = keyAgent.bkDetachedRepubForeignSign( user,
			actorFriendClaim.id, bkId, plainMsg );

	bioWrap.returnOkServer( encPacket );
}

void Server::repubRemoteBroadcastAuthor( User &user,
		Identity &actorId, FriendClaim &friendClaim,
		const String &publisher, const String &messageId,
		const String &network, long long generation,
		const String &recipients )
{
	Identity publisherId( mysql, publisher );

	DbQuery find( mysql,
		"SELECT plain_message FROM remote_broadcast_response "
		"WHERE user_id = %L AND publisher_id = %L AND message_id = %e ",
		user.id(), publisherId.id(), messageId()
	);

	if ( find.rows() != 1 )
		throw InvalidRemoteBroadcastResponse();

	MYSQL_ROW row = find.fetchRow();
	u_long *lengths = find.fetchLengths();
	String plainMsg = Pointer( row[0], lengths[0] );

	FriendClaim actorFriendClaim( mysql, user, actorId );

	String userIduri = user.iduri;
	Identity authorId( mysql, userIduri );

	PacketRecipientList epp( recipients );

	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT get_broadcast_key.id "
		"FROM get_broadcast_key "
		"WHERE friend_claim_id = %L AND "
		"	network_dist = %e AND generation = %L ",
		friendClaim.id, network(), generation );

	if ( recipient.rows() == 0 )
		throw BroadcastRecipientInvalid();

	row = recipient.fetchRow();
	long long bkId = parseId( row[0] );

	String encPacket = keyAgent.bkDetachedRepubForeignSign( user,
			actorFriendClaim.id, bkId, plainMsg );

	bioWrap.returnOkServer( encPacket );
}

void Server::repubRemoteBroadcastSubject( User &user,
		Identity &actorId, FriendClaim &friendClaim,
		const String &publisher, const String &messageId,
		const String &network, long long generation,
		const String &recipients )
{
	Identity publisherId( mysql, publisher );

	DbQuery find( mysql,
		"SELECT plain_message FROM remote_broadcast_subject "
		"WHERE user_id = %L AND publisher_id = %L AND message_id = %e ",
		user.id(), publisherId.id(), messageId()
	);

	if ( find.rows() != 1 )
		throw InvalidRemoteBroadcastSubject();
	
	MYSQL_ROW row = find.fetchRow();
	u_long *lengths = find.fetchLengths();
	String plainMsg = Pointer( row[0], lengths[0] );

	FriendClaim actorFriendClaim( mysql, user, actorId );

	String userIduri = user.iduri;
	Identity subjectId( mysql, userIduri );

	PacketRecipientList epp( recipients );

	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT get_broadcast_key.id "
		"FROM get_broadcast_key "
		"WHERE friend_claim_id = %L AND "
		"	network_dist = %e AND generation = %L ",
		friendClaim.id, network(), generation );

	if ( recipient.rows() == 0 )
		throw BroadcastRecipientInvalid();

	row = recipient.fetchRow();
	long long bkId = parseId( row[0] );

	String encPacket = keyAgent.bkDetachedRepubForeignSign( user,
			actorFriendClaim.id, bkId, plainMsg );

	bioWrap.returnOkServer( encPacket );
}

bool Server::deliverBroadcast()
{
	/* Try to find a message. */
	DbQuery findOne( mysql, 
		"SELECT id, relid, dist_name, generation, message "
		"FROM received_broadcast "
		"WHERE reprocess ORDER by id LIMIT 1"
	);

	if ( findOne.rows() == 0 )
		return false;

	MYSQL_ROW row = findOne.fetchRow();
	u_long *lengths = findOne.fetchLengths();

	long long id = parseId( row[0] );
	String relid = Pointer( row[1], lengths[1] );
	String distName = Pointer( row[2], lengths[2] );
	long long generation = parseId( row[3] );
	String msg = Pointer( row[4], lengths[4] );

	/* Remove it. If removing fails then we assume that some other process
	 * removed the item. */
	DbQuery remove( mysql, 
		"DELETE FROM received_broadcast "
		"WHERE id = %L", id
	);
	int affected = remove.affectedRows();

	if ( affected == 1 )
		receiveBroadcast( relid, distName, generation, msg );

	return true;
}

void Server::fetchRbBroadcastKey( User &user, Identity &friendId,
		FriendClaim &friendClaim, Identity &senderId, const String &distName,
		long long generation, const String &memberProof )
{
	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT get_broadcast_key.id "
		"FROM get_broadcast_key "
		"WHERE friend_claim_id = %L AND "
		"	network_dist = %e AND generation = %L ",
		friendClaim.id, distName(), generation );

	if ( recipient.rows() == 0 )
		throw BroadcastRecipientInvalid();

	MYSQL_ROW row = recipient.fetchRow();
	long long bkId = parseId( row[0] );

	String rbSigKey = keyAgent.getFriendClaimRbSigKey( friendClaim.id, 
			friendId.id(), senderId.iduri, bkId, memberProof );

	String encRbSigKeyHash = keyAgent.signEncrypt( senderId, user, rbSigKey );

	bioWrap.returnOkServer( encRbSigKeyHash );
}
