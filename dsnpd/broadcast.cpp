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

void Server::broadcastReceipient( MYSQL *mysql, RecipientList &recipients, const char *relid )
{
	recipients.push_back( std::string(relid) );
	bioWrap->printf( "OK\r\n" );
}

void directBroadcast( MYSQL *mysql, const char *relid, const char *user, 
		const char *network, const char *authorId, long long seqNum,
		const char *date, const char *msg, long mLen )
{
	String args( "notification_broadcast %s %s %lld %s %ld", 
			user, authorId, seqNum, date, mLen );
	appNotification( args, msg, mLen );
}

void remoteInner( MYSQL *mysql, const char *user, const char *network,
		const char *subjectId, const char *authorId, long long seqNum,
		const char *date, const char *msg, long mLen )
{
	String args( "notification_remote_message %s %s %s %lld %s %ld", 
			user, subjectId, authorId, seqNum, date, mLen );
	appNotification( args, msg, mLen );
}

void storeFriendLink( MYSQL *mysql, const char *user, long long networkId, const char *from, const char *to )
{
	DbQuery findFrom( mysql,
		"SELECT id FROM friend_claim WHERE user = %e AND iduri = %e",
		user, from );

	DbQuery findTo( mysql,
		"SELECT id FROM friend_claim WHERE user = %e AND iduri = %e",
		user, to );

	if ( findFrom.rows() > 0 && findTo.rows() > 0 ) {
		long long fromId = strtoll( findFrom.fetchRow()[0], 0, 10 );
		long long toId = strtoll( findTo.fetchRow()[0], 0, 10 );

		DbQuery( mysql,
			"INSERT IGNORE INTO friend_link "
			"( network_id, from_fc_id, to_fc_id ) "
			"VALUES ( %L, %L, %L ) ",
			networkId, fromId, toId );
	}
}

void friendProofBroadcast( MYSQL *mysql, const char *user, 
		const char *group, long long networkId, const char *subjectId, const char *authorId,
		long long seqNum, const char *fromId, const char *toId, const char *date )
{
	message("%s received friend proof subject_id %s author_id %s date %s\n",
		user, subjectId, authorId, date );

	/* Check that the ids in the link mesage are about the subject and author
	 * (which are verified). */
	if ( strcmp( fromId, subjectId ) == 0 && strcmp( toId, authorId ) == 0 )
		storeFriendLink( mysql, user, networkId, fromId, toId );
	else if ( strcmp( fromId, authorId ) == 0 && strcmp( toId, subjectId ) == 0 )
		storeFriendLink( mysql, user, networkId, fromId, toId );
}

void Server::remoteBroadcast( MYSQL *mysql, User &user, Identity &identity,
		const char *hash, const char *network, long long networkId, long long generation,
		const char *msg, long mLen )
{
	Identity innerIdentity( mysql, Identity::ByHash(), hash );

	DbQuery recipient( mysql,
		"SELECT broadcast_key "
		"FROM friend_claim "
		"JOIN get_broadcast_key ON friend_claim.id = get_broadcast_key.friend_claim_id "
		"WHERE user_id = %L AND identity_id = %L AND network_dist = %e AND generation = %L",
		user.id(), innerIdentity.id(), network, generation );

	if ( recipient.rows() > 0 ) {
		message( "remote broadcast: found recipient for inner messsage\n");
		MYSQL_ROW row = recipient.fetchRow();
		const char *broadcastKey = row[0];

		/* Do the decryption. */
		Keys *idPub = innerIdentity.fetchPublicKey();
		Encrypt encrypt( idPub, 0 );
		encrypt.bkDecryptVerify( broadcastKey, msg, mLen );

		RemoteBroadcastParser rbp;
		rbp.parse( (char*)encrypt.decrypted, encrypt.decLen );
		switch ( rbp.type ) {
			case RemoteBroadcastParser::RemoteInner:
				remoteInner( mysql, user.user(), network, identity.iduri, innerIdentity.iduri, rbp.seq_num, 
						rbp.date, rbp.embeddedMsg, rbp.length );
				break;
			default:
				error("remote broadcast parse failed: %.*s\n", 
						(int)encrypt.decLen, (char*)encrypt.decrypted );
				break;
		}
	}
}

void Server::receiveBroadcast( MYSQL *mysql, const char *relid, const char *network, 
		long long keyGen, const char *encrypted )
{
	FriendClaim friendClaim( mysql, relid );
	User user( mysql, friendClaim.userId );
	Identity identity( mysql, friendClaim.identityId );

	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT broadcast_key "
		"FROM get_broadcast_key "
		"WHERE friend_claim_id = %L AND network_dist = %e AND generation = %L ",
		friendClaim.id, network, keyGen );

	if ( recipient.rows() == 0 )
		throw BroadcastRecipientInvalid();

	MYSQL_ROW row = recipient.fetchRow();
	String broadcastKey = row[0];

	/* Do the decryption. */
	Keys *idPub = identity.fetchPublicKey();
	Encrypt encrypt( idPub, 0 );
	encrypt.bkDecryptVerify( broadcastKey, encrypted, strlen(encrypted) );

	/* Take a copy of the decrypted message. */
	char *decrypted = new char[encrypt.decLen+1];
	memcpy( decrypted, encrypt.decrypted, encrypt.decLen );
	decrypted[encrypt.decLen] = 0;
	int decLen = encrypt.decLen;

	BroadcastParser bp;
	bp.parse( decrypted, decLen );
	switch ( bp.type ) {
		case BroadcastParser::Direct:
			directBroadcast( mysql, relid, user.user(), network, identity.iduri, 
					bp.seq_num, bp.date, bp.embeddedMsg, bp.length );
			break;
		case BroadcastParser::Remote:
			remoteBroadcast( mysql, user, identity, bp.hash, 
					bp.distName, 1, bp.generation, bp.embeddedMsg, bp.length );
			break;
		default:
			break;
	}

	bioWrap->printf( "OK\r\n" );
}

void Server::receiveBroadcast( MYSQL *mysql, RecipientList &recipients, const char *group,
		long long keyGen, const char *encrypted )
{
	for ( RecipientList::iterator r = recipients.begin(); r != recipients.end(); r++ )
		receiveBroadcast( mysql, r->c_str(), group, keyGen, encrypted );
}

long storeBroadcastRecipients( MYSQL *mysql, User &user,
	long long messageId, DbQuery &recipients )
{
	String lastSite;
	long long lastQueueId = -1;
	long count = 0;

	while ( true ) {
		MYSQL_ROW row = recipients.fetchRow();
		if ( !row )
			break;
		
		long long id = parseId( row[0] );
		char *iduri = row[1];
		char *putRelid = row[2];

		message( "send to %s %s\n", iduri, putRelid );
		Identity identity( id, iduri );

		/* If we need a new host then add it. */
		if ( lastSite.length == 0 || strcmp( lastSite(), identity.site() ) != 0 ) {
			DbQuery( mysql,
				"INSERT INTO broadcast_queue "
				"( message_id, send_after, to_host, to_site ) "
				"VALUES ( %L, NOW(), %e, %e ) ",
				messageId, identity.host(), identity.site() );

			lastQueueId = lastInsertId( mysql );
			lastSite.set( identity.site() );
		}

		/* Insert the recipient. */
		DbQuery( mysql,
			"INSERT INTO broadcast_recipient "
			"( queue_id, relid ) "
			"VALUES ( %L, %e ) ",
			lastQueueId, putRelid );

		count += 1;
	}
	return count;
}

void queueBroadcast( MYSQL *mysql, User &user, const char *msg, long mLen )
{
	/* Get the latest put session key. */
	long long networkId = findPrimaryNetworkId( mysql, user );
	PutKey put( mysql, networkId );

	/* Do the encryption. */ 
	Keys *userPriv = loadKey( mysql, user ); 
	Encrypt encrypt( 0, userPriv ); 
	encrypt.bkSignEncrypt( put.broadcastKey, (u_char*)msg, mLen ); 

	/* Stroe the message. */
	DbQuery( mysql,
		"INSERT INTO broadcast_message "
		"( dist_name, key_gen, message ) "
		"VALUES ( %e, %L, %e ) ",
		put.distName(), put.generation, encrypt.sym );

	long long messageId = lastInsertId( mysql );

	/*
	 * Out-of-tree broadcasts.
	 */
	DbQuery outOfTree( mysql,
		"SELECT identity.id, identity.iduri, friend_claim.put_relid "
		"FROM friend_claim "
		"JOIN identity ON friend_claim.identity_id = identity.id "
		"JOIN network_member "
		"ON friend_claim.id = network_member.friend_claim_id "
		"WHERE friend_claim.user_id = %L AND network_member.network_id = %L ",
		user.id(), networkId );

	storeBroadcastRecipients( mysql, user, messageId, outOfTree );
}


void Server::submitBroadcast( MYSQL *mysql, const char *_user, 
		const char *msg, long mLen )
{
	String timeStr = timeNow();
	String authorId( "%s%s/", c->CFG_URI, _user );

	User user( mysql, _user );
	Identity author( mysql, authorId );

	/* insert the broadcast message into the published table. */
	DbQuery( mysql,
		"INSERT INTO broadcasted "
		"( user_id, author_id, time_published ) "
		"VALUES ( %L, %L, %e )",
		user.id(), author.id(), timeStr.data );

	long long seqNum = lastInsertId( mysql );

	/* Make the full message. */
	String broadcastCmd(
		"direct_broadcast %lld %s %ld\r\n",
		seqNum, timeStr.data, mLen );
	String full = addMessageData( broadcastCmd, msg, mLen );

	queueBroadcast( mysql, user, full.data, full.length );
	bioWrap->printf( "OK\r\n" );
}


void sendRemoteBroadcast( MYSQL *mysql, User &user,
		const char *authorHash, const char *network, long long generation,
		long long seqNum, const char *encMessage )
{
	long encMessageLen = strlen(encMessage);

	/* Make the full message. */
	String command( 
		"remote_broadcast %s %s %lld %lld %ld\r\n", 
		authorHash, network, generation, seqNum, encMessageLen );
	String full = addMessageData( command, encMessage, encMessageLen );

	queueBroadcast( mysql, user, full.data, full.length );
}

void Server::remoteBroadcastRequest( MYSQL *mysql, const char *toUser, 
		const char *authorId, const char *authorHash, 
		const char *token, const char *msg, long mLen )
{
	/* Get the current time. */
	String timeStr = timeNow();

	User user( mysql, toUser );
	Identity identity( mysql, authorId );
	FriendClaim friendClaim( mysql, user, identity );

	String subjectId( "%s%s/", c->CFG_URI, toUser );

	/* FIXME: sequence number is not right. */
//	/* Insert the broadcast message into the published table. */
//	DbQuery( mysql,
//		"INSERT INTO broadcasted "
//		"( user_id, author_id, subject_id, time_published, message ) "
//		"VALUES ( %e, %e, %e, %e, %d )",
//		toUser, authorId, subjectId.data, timeStr.data, msg, mLen );

	/* Get the id that was assigned to the message. */
	long long seqNum = lastInsertId( mysql );

	Keys *userPriv = loadKey( mysql, toUser );
	Keys *idPub = identity.fetchPublicKey();

	Encrypt encrypt;
	encrypt.load( idPub, userPriv );
	encrypt.signEncrypt( (u_char*)msg, mLen );

	String remotePublishCmd(
		"encrypt_remote_broadcast %s %lld %ld\r\n%s\r\n", 
		token, seqNum, mLen, msg );
	
	char *result = 0;
	sendMessageNow( mysql, false, toUser, authorId, friendClaim.putRelid(),
			remotePublishCmd, &result );
	
	if ( result == 0 )
		throw ParseError();
	
	//returned_reqid_parser( mysql, to_user, result );
	String hash = makeIduriHash( identity.iduri );

	DbQuery( mysql,
		"INSERT INTO pending_remote_broadcast "
		"( user_id, identity_id, hash, reqid, seq_num ) "
		"VALUES ( %L, %L, %e, %e, %L )",
		user.id(), identity.id(), hash(), result, seqNum );

	message("send_message_now returned: %s\n", result );
	bioWrap->printf( "OK %s\r\n", result );
}

void Server::remoteBroadcastResponse( MYSQL *mysql, const char *_user, const char *reqid )
{
	User user( mysql, _user );

	DbQuery recipient( mysql, 
		"SELECT identity_id, network_dist, generation, sym "
		"FROM remote_broadcast_request "
		"WHERE user_id = %L AND reqid = %e",
		user.id(), reqid );
	
	if ( recipient.rows() == 0 )
		throw RequestIdInvalid();

	MYSQL_ROW row = recipient.fetchRow();
	long long identityId = parseId( row[0] );
	const char *networkDist = row[1];
	const char *generation = row[2];
	const char *sym = row[3];
	message( "flushing remote with reqid: %s\n", reqid );

	Identity identity( mysql, identityId );
	FriendClaim friendClaim( mysql, user, identity );

	String returnCmd( "return_remote_broadcast %s %s %s %s\r\n", reqid, networkDist, generation, sym );

	message("lengths %ld %ld\n", strlen(returnCmd.data), returnCmd.length );

	char *result = 0;
	sendMessageNow( mysql, false, user.user(), identity.iduri(), friendClaim.putRelid(), returnCmd.data, &result );

	if ( result == 0 )
		throw ParseError();

	/* Clear the pending remote broadcast. */
	DbQuery clear( mysql, 
		"DELETE FROM remote_broadcast_request "
		"WHERE user_id = %L AND reqid = %e",
		user.id(), reqid );

	bioWrap->printf( "OK %s\r\n", result );
}

void Server::returnRemoteBroadcast( MYSQL *mysql, User &user, Identity &identity, 
		const char *reqid, const char *networkDist, long long generation, const char *sym )
{
	u_char reqid_final[REQID_SIZE];
	RAND_bytes( reqid_final, REQID_SIZE );
	const char *reqid_final_str = binToBase64( reqid_final, REQID_SIZE );

	DbQuery recipient( mysql, 
		"UPDATE pending_remote_broadcast "
		"SET network_dist = %e, generation = %L, sym = %e, reqid_final = %e"
		"WHERE user_id = %L AND identity_id = %L AND reqid = %e ",
		networkDist, generation, sym, reqid_final_str, user.id(), identity.id(), reqid );

	bioWrap->printf( "OK %s\r\n", reqid_final_str );
}

void Server::remoteBroadcastFinal( MYSQL *mysql, const char *_user, const char *reqid )
{
	User user( mysql, _user );

	DbQuery recipient( mysql, 
		"SELECT identity_id, hash, seq_num, network_dist, generation, sym "
		"FROM pending_remote_broadcast "
		"WHERE user_id = %L AND reqid_final = %e",
		user.id(), reqid );
	
	if ( recipient.rows() == 1 ) {
		MYSQL_ROW row = recipient.fetchRow();
		long long identityId = parseId( row[0] );
		const char *hash = row[1];
		const char *seq_num = row[2];
		const char *network = row[3];
		const char *generation = row[4];
		const char *sym = row[5];

		Identity identity( mysql, identityId );

		sendRemoteBroadcast( mysql, user, hash, network,
				strtoll(generation, 0, 10), strtoll(seq_num, 0, 10), sym );

		/* Clear the pending remote broadcast. */
		DbQuery clear( mysql, 
			"DELETE FROM pending_remote_broadcast "
			"WHERE user_id = %L AND reqid_final = %e",
			user.id(), reqid );
	}

	bioWrap->printf( "OK\r\n" );
}

void Server::encryptRemoteBroadcast( MYSQL *mysql, User &user,
		Identity &subjectId, const char *token,
		long long seqNum, const char *msg, long mLen )
{
	DbQuery flogin( mysql,
		"SELECT id FROM remote_flogin_token "
		"WHERE user_id = %L AND identity_id = %L AND login_token = %e",
		user.id(), subjectId.id(), token );

	if ( flogin.rows() == 0 )
		throw LoginTokenNotValid();

	/* Get the current time. */
	String timeStr = timeNow();

	Keys *userPriv = loadKey( mysql, user.user() );
	Keys *idPub = subjectId.fetchPublicKey();

	/* Notifiy the frontend. */
	String args( "notification_remote_publication %s %s %ld", 
			user.user(), subjectId.iduri(), mLen );
	appNotification( args, msg, mLen );

	/* Find current generation and youngest broadcast key */
	long long networkId = findPrimaryNetworkId( mysql, user );
	PutKey put( mysql, networkId );

	/* Make the full message. */
	String command( "remote_inner %lld %s %ld\r\n",
		seqNum, timeStr.data, mLen );
	String full = addMessageData( command, msg, mLen );

	Encrypt encrypt;
	encrypt.load( idPub, userPriv );
	encrypt.bkSignEncrypt( put.broadcastKey, 
			(u_char*)full.data, full.length );

	u_char reqid[REQID_SIZE];
	RAND_bytes( reqid, REQID_SIZE );
	const char *reqidStr = binToBase64( reqid, REQID_SIZE );

	DbQuery( mysql,
		"INSERT INTO remote_broadcast_request "
		"	( user_id, identity_id, reqid, network_dist, generation, sym ) "
		"VALUES ( %L, %L, %e, %e, %L, %e )",
		user.id(), subjectId.id(), reqidStr,
		put.distName(), put.generation, encrypt.sym );

	bioWrap->printf( "OK %s\r\n", reqidStr );
}

