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

void broadcastReceipient( MYSQL *mysql, RecipientList &recipients, const char *relid )
{
	recipients.push_back( std::string(relid) );
	BIO_printf( bioOut, "OK\r\n" );
}

void directBroadcast( MYSQL *mysql, const char *relid, const char *user, 
		const char *network, const char *authorId, long long seqNum,
		const char *date, const char *msg, long mLen )
{
	String args( "notification_broadcast %s %s %lld %s %ld", 
			user, authorId, seqNum, date, mLen );
	appNotification( args, msg, mLen );
}

void groupMemberRevocation( MYSQL *mysql, const char *user, 
		const char *friendId, const char *network, long long networkId,
		long long generation, const char *revokedId )
{
	DbQuery findFrom( mysql,
		"SELECT id FROM friend_claim WHERE user = %e AND iduri = %e",
		user, friendId );

	DbQuery findTo( mysql,
		"SELECT id FROM friend_claim WHERE user = %e AND iduri = %e",
		user, revokedId );

	if ( findFrom.rows() > 0 && findTo.rows() > 0 ) {
		long long fromId = strtoll( findFrom.fetchRow()[0], 0, 10 );
		long long toId = strtoll( findTo.fetchRow()[0], 0, 10 );

		DbQuery remove( mysql,
			"DELETE FROM friend_link "
			"WHERE network_id = %L AND from_fc_id = %L AND to_fc_id = %L ",
			networkId, fromId, toId );
	}
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

void remoteBroadcast( MYSQL *mysql, User &user, Identity &identity,
		const char *hash, const char *network, long long networkId, long long generation,
		const char *msg, long mLen )
{
	message( "remote broadcast: user %s hash %s network %s generation %lld\n", user.user(), hash, network, generation );

	Identity innerIdentity( mysql, Identity::ByHash(), hash );

	DbQuery recipient( mysql,
		"SELECT broadcast_key "
		"FROM friend_claim "
		"JOIN get_broadcast_key ON friend_claim.id = get_broadcast_key.friend_claim_id "
		"WHERE user_id = %L AND identity_id = %L AND network_dist = %e AND generation = %L",
		user.id(), innerIdentity.id(), network, generation );

	message(
		"SELECT broadcast_key "
		"FROM friend_claim "
		"JOIN get_broadcast_key ON friend_claim.id = get_broadcast_key.friend_claim_id "
		"WHERE user_id = %lld AND identity_id = %lld AND network_dist = '%s' AND generation = %lld\n",
		user.id(), innerIdentity.id(), network, generation );

	if ( recipient.rows() > 0 ) {
		message( "remote broadcast: found recipient for inner messsage\n");
		MYSQL_ROW row = recipient.fetchRow();
		const char *broadcastKey = row[0];

		/* Do the decryption. */
		Keys *idPub = innerIdentity.fetchPublicKey();
		Encrypt encrypt( idPub, 0 );
		int decryptRes = encrypt.bkDecryptVerify( broadcastKey, msg, mLen );

		if ( decryptRes < 0 ) {
			error("second level broadcast decrypt verify failed with %s\n", encrypt.err);
			BIO_printf( bioOut, "ERROR\r\n" );
			return;
		}

		RemoteBroadcastParser rbp;
		rbp.parse( (char*)encrypt.decrypted, encrypt.decLen );
		switch ( rbp.type ) {
			case RemoteBroadcastParser::RemoteInner:
				remoteInner( mysql, user.user(), network, identity.iduri, innerIdentity.iduri, rbp.seq_num, 
						rbp.date, rbp.embeddedMsg, rbp.length );
				break;
			case RemoteBroadcastParser::FriendProof:
//				friendProofBroadcast( mysql, user, network, networkId, friendId, authorId,
//						rbp.seq_num, rbp.identity1, rbp.identity2, rbp.date );
//				break;
			default:
				error("remote broadcast parse failed: %.*s\n", 
						(int)encrypt.decLen, (char*)encrypt.decrypted );
				break;
		}
	}
}

/* This could be optimized to only store into broadcast_queue when sites differ. */
long long forwardBroadcast( MYSQL *mysql, long long messageId, 
		String lastSite, long long &lastQueueId,
		const char *site, const char *relid )
{
	if ( lastSite.length == 0 || strcmp( lastSite.data, site ) != 0 ) {
		DbQuery( mysql,
			"INSERT INTO broadcast_queue "
			"( message_id, send_after, to_site, forward ) "
			"VALUES ( %L, NOW(), %e, true ) ",
			messageId, site );

		lastQueueId = lastInsertId( mysql );
		lastSite.set( site );
	}

	/* Insert the recipient. */
	DbQuery( mysql,
		"INSERT INTO broadcast_recipient "
		"( queue_id, relid ) "
		"VALUES ( %L, %e ) ",
		lastQueueId, relid );

	return lastQueueId;
}

void receiveBroadcast( MYSQL *mysql, const char *relid, const char *network, 
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

	if ( recipient.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR bad recipient\r\n");
		return;
	}

	message( "encrypted: %ld %s\n", strlen(encrypted), encrypted );

	MYSQL_ROW row = recipient.fetchRow();
	String broadcastKey = row[0];

	/* Do the decryption. */
	Keys *idPub = identity.fetchPublicKey();
	Encrypt encrypt( idPub, 0 );
	int decryptRes = encrypt.bkDecryptVerify( broadcastKey, encrypted, strlen(encrypted) );

	if ( decryptRes < 0 ) {
		error("unable to decrypt broadcast message for %s from "
			"%s network %s key gen %lld\n", user.user(), identity.iduri(), network, keyGen );
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}

	/* Take a copy of the decrypted message. */
	char *decrypted = new char[encrypt.decLen+1];
	memcpy( decrypted, encrypt.decrypted, encrypt.decLen );
	decrypted[encrypt.decLen] = 0;
	int decLen = encrypt.decLen;

	BroadcastParser bp;
	int parseRes = bp.parse( decrypted, decLen );
	if ( parseRes < 0 )
		error("broadcast_parser failed\n");
	else {
		switch ( bp.type ) {
			case BroadcastParser::Direct:
				directBroadcast( mysql, relid, user.user(), network, identity.iduri, 
						bp.seq_num, bp.date, bp.embeddedMsg, bp.length );
				break;
			case BroadcastParser::Remote:
				remoteBroadcast( mysql, user, identity, bp.hash, 
						bp.network, 1, bp.generation, bp.embeddedMsg, bp.length );
				break;
			case BroadcastParser::GroupMemberRevocation:
	//			groupMemberRevocation( mysql, user, friendId,
	//					bp.network, networkId, bp.generation, bp.identity );
			default:
				break;
		}
	}

	BIO_printf( bioOut, "OK\r\n" );
}

void receiveBroadcast( MYSQL *mysql, RecipientList &recipients, const char *group,
		long long keyGen, const char *encrypted )
{
	for ( RecipientList::iterator r = recipients.begin(); r != recipients.end(); r++ )
		receiveBroadcast( mysql, r->c_str(), group, keyGen, encrypted );
}

long storeBroadcastRecipients( MYSQL *mysql, const char *user, 
	long long messageId, DbQuery &recipients )
{
	String lastSite;
	long long lastQueueId = -1;
	long count = 0;

	while ( true ) {
		MYSQL_ROW row = recipients.fetchRow();
		if ( !row )
			break;
		
		char *friendId = row[0];
		char *putRelid = row[1];
		message( "send to %s %s\n", friendId, putRelid );

		IdentityOrig id( friendId );
		id.parse();

		/* If we need a new host then add it. */
		if ( lastSite.length == 0 || strcmp( lastSite.data, id.site ) != 0 ) {
			DbQuery( mysql,
				"INSERT INTO broadcast_queue "
				"( message_id, send_after, to_site ) "
				"VALUES ( %L, NOW(), %e ) ",
				messageId, id.site );

			lastQueueId = lastInsertId( mysql );
			lastSite.set( id.site );
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
		
		char *friendId = row[0];
		char *putRelid = row[1];

		message( "send to %s %s\n", friendId, putRelid );

		IdentityOrig id( friendId );
		id.parse();

		/* If we need a new host then add it. */
		if ( lastSite.length == 0 || strcmp( lastSite.data, id.site ) != 0 ) {
			DbQuery( mysql,
				"INSERT INTO broadcast_queue "
				"( message_id, send_after, to_site ) "
				"VALUES ( %L, NOW(), %e ) ",
				messageId, id.site );

			lastQueueId = lastInsertId( mysql );
			lastSite.set( id.site );
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

long queueBroadcast( MYSQL *mysql, User &user, const char *msg, long mLen )
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
		"SELECT identity.iduri, friend_claim.put_relid "
		"FROM friend_claim "
		"JOIN identity ON friend_claim.identity_id = identity.id "
		"JOIN network_member "
		"ON friend_claim.id = network_member.friend_claim_id "
		"WHERE friend_claim.user_id = %L AND network_member.network_id = %L ",
		user.id(), networkId );

	storeBroadcastRecipients( mysql, user, messageId, outOfTree );

	return 0;
}


long submitBroadcast( MYSQL *mysql, const char *_user, 
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

	long sendResult = queueBroadcast( mysql, user, full.data, full.length );
	if ( sendResult < 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}

	BIO_printf( bioOut, "OK\r\n" );
	return 0;
}


long sendRemoteBroadcast( MYSQL *mysql, User &user,
		const char *authorHash, const char *network, long long generation,
		long long seqNum, const char *encMessage )
{
	long encMessageLen = strlen(encMessage);

	/* Make the full message. */
	String command( 
		"remote_broadcast %s %s %lld %lld %ld\r\n", 
		authorHash, network, generation, seqNum, encMessageLen );
	String full = addMessageData( command, encMessage, encMessageLen );

	long sendResult = queueBroadcast( mysql, user, full.data, full.length );
	if ( sendResult < 0 )
		return -1;

	return 0;
}

long remoteBroadcastRequest( MYSQL *mysql, const char *toUser, 
		const char *authorId, const char *authorHash, 
		const char *token, const char *msg, long mLen )
{
	/* Get the current time. */
	String timeStr = timeNow();

	User user( mysql, toUser );
	Identity identity( mysql, authorId );
	FriendClaim friendClaim( mysql, user, identity );

	String subjectId( "%s%s/", c->CFG_URI, toUser );

//	/* Insert the broadcast message into the published table. */
//	DbQuery( mysql,
//		"INSERT INTO broadcasted "
//		"( user_id, author_id, subject_id, time_published, message ) "
//		"VALUES ( %e, %e, %e, %e, %d )",
//		toUser, authorId, subjectId.data, timeStr.data, msg, mLen );

	/* Get the id that was assigned to the message. */
	DbQuery idQuery( mysql, "SELECT LAST_INSERT_ID()" );
	if ( idQuery.rows() == 0 )
		return -1;

	MYSQL_ROW row = idQuery.fetchRow();
	long long seqNum = strtoll( row[0], 0, 10 );

	Keys *userPriv = loadKey( mysql, toUser );
	Keys *idPub = fetchPublicKey( mysql, authorId );

	Encrypt encrypt;
	encrypt.load( idPub, userPriv );
	encrypt.signEncrypt( (u_char*)msg, mLen );

	String remotePublishCmd(
		"encrypt_remote_broadcast %s %lld %ld\r\n%s\r\n", 
		token, seqNum, mLen, msg );

	char *resultMessage;
	sendMessageNow( mysql, false, toUser, authorId, friendClaim.putRelid(),
			remotePublishCmd.data, &resultMessage );

	//returned_reqid_parser( mysql, to_user, resultMessage );
	String hash = makeIduriHash( identity.iduri );

	DbQuery( mysql,
		"INSERT INTO pending_remote_broadcast "
		"( user_id, identity_id, hash, reqid, seq_num ) "
		"VALUES ( %L, %L, %e, %e, %L )",
		user.id(), identity.id(), hash(), resultMessage, seqNum );

	message("send_message_now returned: %s\n", resultMessage );
	BIO_printf( bioOut, "OK %s\r\n", resultMessage );
	return 0;
}

void remoteBroadcastResponse( MYSQL *mysql, const char *_user, const char *reqid )
{
	User user( mysql, _user );

	DbQuery recipient( mysql, 
		"SELECT identity_id, network_dist, generation, sym "
		"FROM remote_broadcast_request "
		"WHERE user_id = %L AND reqid = %e",
		user.id(), reqid );
	
	if ( recipient.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}

	MYSQL_ROW row = recipient.fetchRow();
	long long identityId = parseId( row[0] );
	const char *networkDist = row[1];
	const char *generation = row[2];
	const char *sym = row[3];
	message( "flushing remote with reqid: %s\n", reqid );

	Identity identity( mysql, identityId );
	FriendClaim friendClaim( mysql, user, identity );

	String returnCmd( "return_remote_broadcast %s %s %s %s\r\n", reqid, networkDist, generation, sym );

	char *result = 0;
	sendMessageNow( mysql, false, user.user(), identity.iduri(), friendClaim.putRelid(), returnCmd.data, &result );

	/* Clear the pending remote broadcast. */
	DbQuery clear( mysql, 
		"DELETE FROM remote_broadcast_request "
		"WHERE user_id = %L AND reqid = %e",
		user.id(), reqid );

	BIO_printf( bioOut, "OK %s\r\n", result );
}

void returnRemoteBroadcast( MYSQL *mysql, User &user, Identity &identity, 
		const char *reqid, const char *networkDist, long long generation, const char *sym )
{
	message("return_remote_broadcast\n");

	u_char reqid_final[REQID_SIZE];
	RAND_bytes( reqid_final, REQID_SIZE );
	const char *reqid_final_str = binToBase64( reqid_final, REQID_SIZE );

	DbQuery recipient( mysql, 
		"UPDATE pending_remote_broadcast "
		"SET network_dist = %e, generation = %L, sym = %e, reqid_final = %e"
		"WHERE user_id = %L AND identity_id = %L AND reqid = %e ",
		networkDist, generation, sym, reqid_final_str, user.id(), identity.id(), reqid );

	BIO_printf( bioOut, "REQID %s\r\n", reqid_final_str );
}

void remoteBroadcastFinal( MYSQL *mysql, const char *_user, const char *reqid )
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

		long res = sendRemoteBroadcast( mysql, user, hash, network,
				strtoll(generation, 0, 10), strtoll(seq_num, 0, 10), sym );
		if ( res < 0 ) {
			BIO_printf( bioOut, "ERROR\r\n" );
			return;
		}

		/* Clear the pending remote broadcast. */
		DbQuery clear( mysql, 
			"DELETE FROM pending_remote_broadcast "
			"WHERE user_id = %L AND reqid_final = %e",
			user.id(), reqid );
	}

	BIO_printf( bioOut, "OK\r\n" );
}

void encryptRemoteBroadcast( MYSQL *mysql, User &user,
		Identity &subjectId, const char *token,
		long long seqNum, const char *msg, long mLen )
{
	DbQuery flogin( mysql,
		"SELECT id FROM remote_flogin_token "
		"WHERE user_id = %L AND identity_id = %L AND login_token = %e",
		user.id(), subjectId.id(), token );

	if ( flogin.rows() == 0 ) {
		error("failed to find user from provided login token\n");
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}

	/* Get the current time. */
	String timeStr = timeNow();

	Keys *userPriv = loadKey( mysql, user.user() );
	Keys *idPub = fetchPublicKey( mysql, subjectId.iduri );

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
	int sigRes = encrypt.bkSignEncrypt( put.broadcastKey, 
			(u_char*)full.data, full.length );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}

	u_char reqid[REQID_SIZE];
	RAND_bytes( reqid, REQID_SIZE );
	const char *reqidStr = binToBase64( reqid, REQID_SIZE );

	DbQuery( mysql,
		"INSERT INTO remote_broadcast_request "
		"	( user_id, identity_id, reqid, network_dist, generation, sym ) "
		"VALUES ( %L, %L, %e, %e, %L, %e )",
		user.id(), subjectId.id(), reqidStr,
		put.distName(), put.generation, encrypt.sym );

	BIO_printf( bioOut, "REQID %s\r\n", reqidStr );
}

