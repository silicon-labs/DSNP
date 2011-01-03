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

void remoteBroadcast( MYSQL *mysql, const char *user, const char *friendId, 
		const char *hash, const char *network, long long networkId, long long generation,
		const char *msg, long mLen )
{
	message( "remote broadcast: user %s hash %s generation %lld\n", user, hash, generation );

	/* Messages has a remote sender and needs to be futher decrypted. */
	DbQuery recipient( mysql, 
		"SELECT friend_claim.id, "
		"	friend_claim.iduri, "
		"	get_broadcast_key.broadcast_key "
		"FROM friend_claim "
		"JOIN get_broadcast_key "
		"ON friend_claim.id = get_broadcast_key.friend_claim_id "
		"WHERE friend_claim.user = %e AND friend_claim.friend_hash = %e AND "
		"	get_broadcast_key.network_id = %L AND get_broadcast_key.generation <= %L "
		"ORDER BY get_broadcast_key.generation DESC LIMIT 1",
		user, hash, networkId, generation );

	if ( recipient.rows() > 0 ) {
		MYSQL_ROW row = recipient.fetchRow();
		//long long friend_claim_id = strtoll(row[0], 0, 10);
		const char *authorId = row[1];
		const char *broadcastKey = row[2];

		/* Do the decryption. */
		Keys *id_pub = fetchPublicKey( mysql, authorId );
		Encrypt encrypt( id_pub, 0 );
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
				remoteInner( mysql, user, network, friendId, authorId, rbp.seq_num, 
						rbp.date, rbp.embeddedMsg, rbp.length );
				break;
			case RemoteBroadcastParser::FriendProof:
				friendProofBroadcast( mysql, user, network, networkId, friendId, authorId,
						rbp.seq_num, rbp.identity1, rbp.identity2, rbp.date );
				break;
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

	MYSQL_ROW row = recipient.fetchRow();
	String broadcastKey = row[0];

	/* Do the decryption. */
	Keys *idPub = identity.fetchPublicKey();
	Encrypt encrypt( idPub, 0 );
	int decryptRes = encrypt.bkDecryptVerify( broadcastKey, encrypted, strlen(encrypted) );

	if ( decryptRes < 0 ) {
		error("unable to decrypt broadcast message for %s from "
			"%s network %s key gen %lld\n", user.user(), friendClaim.id, network, keyGen );
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
	//			remoteBroadcast( mysql, user, friendId, bp.hash, 
	//					bp.network, networkId, bp.generation, bp.embeddedMsg, bp.length );
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

long queueBroadcast( MYSQL *mysql, const char *user, const char *network,
		const char *msg, long mLen )
{
	/* Get the latest put session key. */
	CurrentPutKey put( mysql, user, network );

	/* Do the encryption. */ 
	Keys *userPriv = loadKey( mysql, user ); 
	Encrypt encrypt( 0, userPriv ); 
	encrypt.bkSignEncrypt( put.broadcastKey, (u_char*)msg, mLen ); 

	message( "queue broadcast: encrypting message with %s\n", put.broadcastKey.data );

	/* Stroe the message. */
	DbQuery( mysql,
		"INSERT INTO broadcast_message "
		"( network_name, key_gen, message ) "
		"VALUES ( %e, %L, %e ) ",
		network, put.keyGen, encrypt.sym );

	long long messageId = lastInsertId( mysql );

	/*
	 * Out-of-tree broadcasts.
	 */
	message("finding out-of-tree broadcasts for %s %lld\n", user, put.networkId );
	DbQuery outOfTree( mysql,
		"SELECT friend_claim.iduri, friend_claim.put_relid "
		"FROM friend_claim "
		"JOIN network_member "
		"ON friend_claim.id = network_member.friend_claim_id "
		"WHERE friend_claim.user = %e AND network_member.network_id = %L "
		"ORDER BY friend_claim.iduri",
		user, put.networkId );

	storeBroadcastRecipients( mysql, user, messageId, outOfTree );
	return 0;
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


long sendRemoteBroadcast( MYSQL *mysql, const char *user,
		const char *authorHash, const char *network, long long generation,
		long long seqNum, const char *encMessage )
{
	long encMessageLen = strlen(encMessage);

	/* Make the full message. */
	String command( 
		"remote_broadcast %s %s %lld %lld %ld\r\n", 
		authorHash, network, generation, seqNum, encMessageLen );
	String full = addMessageData( command, encMessage, encMessageLen );

	long sendResult = queueBroadcast( mysql, user, network, full.data, full.length );
	if ( sendResult < 0 )
		return -1;

	return 0;
}

long remoteBroadcastRequest( MYSQL *mysql, const char *toUser, 
		const char *authorId, const char *authorHash, 
		const char *token, const char *network, const char *msg, long mLen )
{
	/* Get the current time. */
	String timeStr = timeNow();

	/* Find the relid from subject to author. */
	DbQuery putRelidQuery( mysql,
			"SELECT put_relid FROM friend_claim WHERE user = %e AND iduri = %e",
			toUser, authorId );
	if ( putRelidQuery.rows() != 1 ) {
		message("find of put_relid from subject to author failed\n");
		return -1;
	}

	String putRelid = putRelidQuery.fetchRow()[0];

	String subjectId( "%s%s/", c->CFG_URI, toUser );

	/* Insert the broadcast message into the published table. */
	DbQuery( mysql,
		"INSERT INTO broadcasted "
		"( user, author_id, subject_id, time_published, message ) "
		"VALUES ( %e, %e, %e, %e, %d )",
		toUser, authorId, subjectId.data, timeStr.data, msg, mLen );

	/* Get the id that was assigned to the message. */
	DbQuery idQuery( mysql, "SELECT LAST_INSERT_ID()" );
	if ( idQuery.rows() == 0 )
		return -1;

	MYSQL_ROW row = idQuery.fetchRow();
	long long seqNum = strtoll( row[0], 0, 10 );

	Keys *user_priv = loadKey( mysql, toUser );
	Keys *id_pub = fetchPublicKey( mysql, authorId );

	Encrypt encrypt;
	encrypt.load( id_pub, user_priv );
	encrypt.signEncrypt( (u_char*)msg, mLen );

	String remotePublishCmd(
		"encrypt_remote_broadcast %s %lld %s %ld\r\n%s\r\n", 
		token, seqNum, network, mLen, msg );

	char *result_message;
	int res = sendMessageNow( mysql, false, toUser, authorId, putRelid.data,
			remotePublishCmd.data, &result_message );
	if ( res < 0 ) {
		message("encrypt_remote_broadcast message failed\n");
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}

	//returned_reqid_parser( mysql, to_user, result_message );

	DbQuery( mysql,
		"INSERT INTO pending_remote_broadcast "
		"( user, identity, hash, reqid, seq_num, network_name ) "
		"VALUES ( %e, %e, %e, %e, %L, %e )",
		toUser, authorId, authorHash, result_message, seqNum, network );

	message("send_message_now returned: %s\n", result_message );
	BIO_printf( bioOut, "OK %s\r\n", result_message );
	return 0;
}

void remote_broadcast_response( MYSQL *mysql, const char *user, const char *reqid )
{
	DbQuery recipient( mysql, 
		"SELECT identity, generation, sym "
		"FROM remote_broadcast_request "
		"WHERE user = %e AND reqid = %e",
		user, reqid );
	
	if ( recipient.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}

	MYSQL_ROW row = recipient.fetchRow();
	const char *identity = row[0];
	const char *generation = row[1];
	const char *sym = row[2];
	message( "flushing remote with reqid: %s\n", reqid );

	/* Find the relid from subject to author. */
	DbQuery putRelidQuery( mysql,
			"SELECT put_relid FROM friend_claim WHERE user = %e AND iduri = %e",
			user, identity );
	if ( putRelidQuery.rows() != 1 ) {
		message("find of put_relid from subject to author failed\n");
		return;
	}

	char *put_relid = putRelidQuery.fetchRow()[0];
	char *result = 0;

	String returnCmd( "return_remote_broadcast %s %s %s\r\n", reqid, generation, sym );
	sendMessageNow( mysql, false, user, identity, put_relid, returnCmd.data, &result );

	/* Clear the pending remote broadcast. */
	DbQuery clear( mysql, 
		"DELETE FROM remote_broadcast_request "
		"WHERE user = %e AND reqid = %e",
		user, reqid );

	BIO_printf( bioOut, "OK %s\r\n", result );
}

void return_remote_broadcast( MYSQL *mysql, const char *user,
		const char *iduri, const char *reqid, long long generation, const char *sym )
{
	message("return_remote_broadcast\n");

	u_char reqid_final[REQID_SIZE];
	RAND_bytes( reqid_final, REQID_SIZE );
	const char *reqid_final_str = binToBase64( reqid_final, REQID_SIZE );

	DbQuery recipient( mysql, 
		"UPDATE pending_remote_broadcast "
		"SET generation = %L, sym = %e, reqid_final = %e"
		"WHERE user = %e AND identity = %e AND reqid = %e ",
		generation, sym, reqid_final_str, user, iduri, reqid );

	BIO_printf( bioOut, "REQID %s\r\n", reqid_final_str );
}

void remoteBroadcastFinal( MYSQL *mysql, const char *user, const char *reqid )
{
	DbQuery recipient( mysql, 
		"SELECT user, identity, hash, seq_num, network_name, generation, sym "
		"FROM pending_remote_broadcast "
		"WHERE user = %e AND reqid_final = %e",
		user, reqid );
	
	if ( recipient.rows() == 1 ) {
		MYSQL_ROW row = recipient.fetchRow();
		const char *user = row[0];
		//const char *identity = row[1];
		const char *hash = row[2];
		const char *seq_num = row[3];
		const char *network = row[4];
		const char *generation = row[5];
		const char *sym = row[6];

		long res = sendRemoteBroadcast( mysql, user, hash, network,
				strtoll(generation, 0, 10), strtoll(seq_num, 0, 10), sym );
		if ( res < 0 ) {
			BIO_printf( bioOut, "ERROR\r\n" );
			return;
		}

		/* Clear the pending remote broadcast. */
		DbQuery clear( mysql, 
			"DELETE FROM pending_remote_broadcast "
			"WHERE user = %e AND reqid_final = %e",
			user, reqid );
	}

	BIO_printf( bioOut, "OK\r\n" );
}

void encryptRemoteBroadcast( MYSQL *mysql, const char *user,
		const char *subjectId, const char *token,
		long long seqNum, const char *network, const char *msg, long mLen )
{
	DbQuery flogin( mysql,
		"SELECT user FROM remote_flogin_token "
		"WHERE user = %e AND identity = %e AND login_token = %e",
		user, subjectId, token );

	if ( flogin.rows() == 0 ) {
		error("failed to find user from provided login token\n");
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}

	/* Get the current time. */
	String timeStr = timeNow();

	Keys *userPriv = loadKey( mysql, user );
	Keys *idPub = fetchPublicKey( mysql, subjectId );

	/* Notifiy the frontend. */
	String args( "notification_remote_publication %s %s %ld", 
			user, subjectId, mLen );
	appNotification( args, msg, mLen );

	/* Find current generation and youngest broadcast key */
	CurrentPutKey put( mysql, user, network );

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
	const char *reqid_str = binToBase64( reqid, REQID_SIZE );

	DbQuery( mysql,
		"INSERT INTO remote_broadcast_request "
		"	( user, identity, reqid, generation, sym ) "
		"VALUES ( %e, %e, %e, %L, %e )",
		user, subjectId, reqid_str, put.keyGen, encrypt.sym );

	BIO_printf( bioOut, "REQID %s\r\n", reqid_str );
}

