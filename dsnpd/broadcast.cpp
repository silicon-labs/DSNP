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

void broadcastReceipient( MYSQL *mysql, RecipientList &recipients, const char *relid )
{
	recipients.push_back( std::string(relid) );
	BIO_printf( bioOut, "OK\r\n" );
}

void direct_broadcast( MYSQL *mysql, const char *relid, const char *user, 
		const char *author_id, long long seq_num, const char *date,
		const char *msg, long mLen )
{
	String args( "user_message %s - %s %lld %s %ld", 
			user, author_id, seq_num, date, mLen );
	app_notification( args, msg, mLen );
}

void remote_inner( MYSQL *mysql, const char *user, const char *subject_id, const char *author_id,
		long long seq_num, const char *date, const char *msg, long mLen )
{
	String args( "user_message %s %s %s %lld %s %ld", 
			user, subject_id, author_id, seq_num, date, mLen );
	app_notification( args, msg, mLen );
}

void friend_proof( MYSQL *mysql, const char *user, const char *subject_id, const char *author_id,
		long long seq_num, const char *date )
{
	message("%s received friend proof subject_id %s author_id %s date %s\n",
		user, subject_id, author_id, date );

	String args( "friend_proof %s %s %s %lld %s", 
			user, subject_id, author_id, seq_num, date );
	app_notification( args, 0, 0 );
}

void remote_broadcast( MYSQL *mysql, const char *user, const char *friend_id, 
		const char *hash, long long generation, const char *msg, long mLen )
{
	message( "remote_broadcast: user %s hash %s generation %lld\n", user, hash, generation );

	/* Messages has a remote sender and needs to be futher decrypted. */
	DbQuery recipient( mysql, 
		"SELECT friend_claim.id, "
		"	friend_claim.friend_id, "
		"	get_broadcast_key.broadcast_key "
		"FROM friend_claim "
		"JOIN get_broadcast_key "
		"ON friend_claim.id = get_broadcast_key.friend_claim_id "
		"WHERE friend_claim.user = %e AND friend_claim.friend_hash = %e AND "
		"	get_broadcast_key.generation <= %L "
		"ORDER BY get_broadcast_key.generation DESC LIMIT 1",
		user, hash, generation );

	if ( recipient.rows() > 0 ) {
		MYSQL_ROW row = recipient.fetchRow();
		//long long friend_claim_id = strtoll(row[0], 0, 10);
		const char *author_id = row[1];
		const char *broadcast_key = row[2];

		message( "remote_broadcast: have recipient\n");

		/* Do the decryption. */
		RSA *id_pub = fetch_public_key( mysql, author_id );
		Encrypt encrypt( id_pub, 0 );
		int decryptRes = encrypt.bkDecryptVerify( broadcast_key, msg );

		if ( decryptRes < 0 ) {
			message("second level bkDecryptVerify failed with %s\n", encrypt.err);
			BIO_printf( bioOut, "ERROR\r\n" );
			return;
		}

		message( "second level broadcast_key: %s  author_id: %s  decLen: %d\n", 
				broadcast_key, author_id, encrypt.decLen );

		RemoteBroadcastParser rbp;
		rbp.parse( (char*)encrypt.decrypted, encrypt.decLen );
		switch ( rbp.type ) {
			case RemoteBroadcastParser::RemoteInner:
				remote_inner( mysql, user, friend_id, author_id, rbp.seq_num, 
						rbp.date, rbp.embeddedMsg, rbp.length );
				break;
			case RemoteBroadcastParser::FriendProof:
				friend_proof( mysql, user, friend_id, author_id, rbp.seq_num, rbp.date );
				break;
			default:
				error("remote broadcast parse failed\n");
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

void receiveBroadcast( MYSQL *mysql, const char *relid, long long keyGen,
		bool forward, long long treeGenLow, long long treeGenHigh, const char *encrypted )
{
	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT friend_claim.id, "
		"	friend_claim.user, "
		"	friend_claim.friend_id, "
		"	get_broadcast_key.broadcast_key "
		"FROM friend_claim "
		"JOIN get_broadcast_key "
		"ON friend_claim.id = get_broadcast_key.friend_claim_id "
		"WHERE friend_claim.get_relid = %e AND get_broadcast_key.generation <= %L "
		"ORDER BY get_broadcast_key.generation DESC LIMIT 1",
		relid, keyGen );

	if ( recipient.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR bad recipient\r\n");
		return;
	}

	MYSQL_ROW row = recipient.fetchRow();
	unsigned long long friendClaimId = strtoull(row[0], 0, 10);
	const char *user = row[1];
	const char *friendId = row[2];
	const char *broadcastKey = row[3];

	/* Do the decryption. */
	RSA *id_pub = fetch_public_key( mysql, friendId );
	Encrypt encrypt( id_pub, 0 );
	int decryptRes = encrypt.bkDecryptVerify( broadcastKey, encrypted );

	if ( decryptRes < 0 ) {
		error("unable to decrypt broadcast message relid %s key gen %lld\n", relid, keyGen );
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
				direct_broadcast( mysql, relid, user, friendId, bp.seq_num, 
						bp.date, bp.embeddedMsg, bp.length );
				break;
			case BroadcastParser::Remote:
				remote_broadcast( mysql, user, friendId, bp.hash, 
						bp.generation, bp.embeddedMsg, bp.length );
				break;
			default:
				break;
		}
	}

	if ( forward ) {
		/* 
		 * Now do the forwarding.
		 */

		DbQuery forward( mysql, 
			"SELECT "
			"	site1, relid1, "
			"	site2, relid2 "
			"FROM get_tree "
			"WHERE friend_claim_id = %L AND "
			"	%L << generation AND generation <= %L "
			"ORDER BY get_tree.generation DESC LIMIT 1",
			friendClaimId, treeGenLow, treeGenHigh );

		if ( forward.rows() > 0 ) {
			row = forward.fetchRow();
			const char *site1 = row[0];
			const char *relid1 = row[1];
			const char *site2 = row[2];
			const char *relid2 = row[3];

			message("forwarding broadcast message\n");

			long long messageId = -1;
			if ( site1 != 0 || site2 != 0 ) {
				/* Store the message. */
				DbQuery( mysql,
					"INSERT INTO broadcast_message "
					"( key_gen, tree_gen_low, tree_gen_high, message ) "
					"VALUES ( %L, %L, %L, %e ) ",
					keyGen, treeGenLow, treeGenHigh, encrypted );

				messageId = lastInsertId( mysql );
			}

			String lastSite;
			long long lastQueueId = -1;
			if ( site1 != 0 )
				forwardBroadcast( mysql, messageId, lastSite, lastQueueId, site1, relid1 );

			if ( site2 != 0 )
				forwardBroadcast( mysql, messageId, lastSite, lastQueueId, site2, relid2 );
		}
	}
	
	BIO_printf( bioOut, "OK\r\n" );
}


void receiveBroadcast( MYSQL *mysql, RecipientList &recipients, long long keyGen,
		bool forward, long long treeGenLow, long long treeGenHigh, const char *encrypted )
{
	for ( RecipientList::iterator r = recipients.begin(); r != recipients.end(); r++ )
		receiveBroadcast( mysql, r->c_str(), keyGen, forward, treeGenLow, treeGenHigh, encrypted );
}

long storeBroadcastRecipients( MYSQL *mysql, const char *user, long long messageId, 
		DbQuery &recipients, bool forward )
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

		Identity id( friendId );
		id.parse();

		/* If we need a new host then add it. */
		if ( lastSite.length == 0 || strcmp( lastSite.data, id.site ) != 0 ) {
			DbQuery( mysql,
				"INSERT INTO broadcast_queue "
				"( message_id, send_after, to_site, forward ) "
				"VALUES ( %L, NOW(), %e, %b ) ",
				messageId, id.site, forward );

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

long queueBroadcast( MYSQL *mysql, const char *user, const char *msg, long mLen )
{
	/* Get the latest put session key. */
	CurrentPutKey put( mysql, user, "friend" );

	/* Do the encryption. */ 
	RSA *userPriv = load_key( mysql, user ); 
	Encrypt encrypt( 0, userPriv ); 
	encrypt.bkSignEncrypt( put.broadcastKey, (u_char*)msg, mLen ); 

	/* Stroe the message. */
	DbQuery( mysql,
		"INSERT INTO broadcast_message "
		"( key_gen, tree_gen_low, tree_gen_high, message ) "
		"VALUES ( %L, %L, %L, %e ) ",
		put.keyGen, put.treeGenLow, put.treeGenHigh, encrypt.sym );

	long long messageId = lastInsertId( mysql );

	/*
	 * Out-of-tree broadcasts.
	 */
	DbQuery outOfTree( mysql,
		"SELECT friend_claim.friend_id, friend_claim.put_relid "
		"FROM friend_claim "
		"JOIN put_tree "
		"ON friend_claim.id = put_tree.friend_claim_id "
		"WHERE friend_claim.user = %e AND put_tree.state = 1 AND"
		"	%L <= put_tree.generation AND put_tree.generation <= %L "
		"ORDER BY friend_claim.friend_id",
		user, put.treeGenLow, put.treeGenHigh );
	
	storeBroadcastRecipients( mysql, user, messageId, outOfTree, false );
	

	/*
	 * In-tree broadcasts.
	 */

	/* Find root friend. */
	DbQuery rootFriend( mysql,
		"SELECT friend_claim.friend_id, friend_claim.put_relid "
		"FROM friend_claim "
		"JOIN put_tree "
		"ON friend_claim.id = put_tree.friend_claim_id "
		"WHERE friend_claim.user = %e AND put_tree.root = true AND"
		"	%L <= put_tree.generation AND put_tree.generation <= %L "
		"ORDER BY friend_claim.friend_id",
		user, put.treeGenLow, put.treeGenHigh );

	storeBroadcastRecipients( mysql, user, messageId, rootFriend, true );

	return 0;
}


long submitBroadcast( MYSQL *mysql, const char *user, const char *msg, long mLen )
{
	String timeStr = timeNow();
	String authorId( "%s%s/", c->CFG_URI, user );

	/* insert the broadcast message into the published table. */
	exec_query( mysql,
		"INSERT INTO broadcasted "
		"( user, author_id, time_published ) "
		"VALUES ( %e, %e, %e )",
		user, authorId.data, timeStr.data );

	/* Get the id that was assigned to the message. */
	DbQuery lastInsertId( mysql, "SELECT LAST_INSERT_ID()" );
	if ( lastInsertId.rows() != 1 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}

	long long seq_num = strtoll( lastInsertId.fetchRow()[0], 0, 10 );

	/* Make the full message. */
	String broadcastCmd(
		"direct_broadcast %lld %s %ld\r\n",
		seq_num, timeStr.data, mLen );
	char *full = new char[broadcastCmd.length + mLen + 2];
	memcpy( full, broadcastCmd.data, broadcastCmd.length );
	memcpy( full + broadcastCmd.length, msg, mLen );
	memcpy( full + broadcastCmd.length + mLen, "\r\n", 2 );

	long sendResult = queueBroadcast( mysql, user, full, broadcastCmd.length + mLen + 2 );
	if ( sendResult < 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}

	BIO_printf( bioOut, "OK\r\n" );
	return 0;
}


long sendRemoteBroadcast( MYSQL *mysql, const char *user,
		const char *author_hash, long long generation,
		long long seq_num, const char *encMessage )
{
	long encMessageLen = strlen(encMessage);
	message("enc message len: %ld\n", encMessageLen);

	/* Make the full message. */
	String command( 
		"remote_broadcast %s %lld %lld %ld\r\n", 
		author_hash, generation, seq_num, encMessageLen );
	String full = addMessageData( command, encMessage, encMessageLen );

	long sendResult = queueBroadcast( mysql, user, full.data, full.length );
	if ( sendResult < 0 )
		return -1;

	return 0;
}

long remote_broadcast_request( MYSQL *mysql, const char *to_user, 
		const char *author_id, const char *author_hash, 
		const char *token, const char *msg, long mLen )
{
	int res;
	RSA *user_priv, *id_pub;
	Encrypt encrypt;
	MYSQL_RES *result;
	MYSQL_ROW row;
	long long seq_num;
	char *result_message;

	/* Get the current time. */
	String timeStr = timeNow();

	/* Find the relid from subject to author. */
	DbQuery putRelidQuery( mysql,
			"SELECT put_relid FROM friend_claim WHERE user = %e AND friend_id = %e",
			to_user, author_id );
	if ( putRelidQuery.rows() != 1 ) {
		message("find of put_relid from subject to author failed\n");
		return -1;
	}

	String putRelid = putRelidQuery.fetchRow()[0];

	String subjectId( "%s%s/", c->CFG_URI, to_user );

	/* Insert the broadcast message into the published table. */
	exec_query( mysql,
		"INSERT INTO broadcasted "
		"( user, author_id, subject_id, time_published, message ) "
		"VALUES ( %e, %e, %e, %e, %d )",
		to_user, author_id, subjectId.data, timeStr.data, msg, mLen );

	/* Get the id that was assigned to the message. */
	exec_query( mysql, "SELECT LAST_INSERT_ID()" );
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row )
		return -1;

	seq_num = strtoll( row[0], 0, 10 );

	user_priv = load_key( mysql, to_user );
	id_pub = fetch_public_key( mysql, author_id );
	encrypt.load( id_pub, user_priv );
	encrypt.signEncrypt( (u_char*)msg, mLen );

	String remotePublishCmd(
		"encrypt_remote_broadcast %s %lld %ld\r\n%s\r\n", 
		token, seq_num, mLen, msg );

	res = sendMessageNow( mysql, false, to_user, author_id, putRelid.data,
			remotePublishCmd.data, &result_message );
	if ( res < 0 ) {
		message("encrypt_remote_broadcast message failed\n");
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}

	//returned_reqid_parser( mysql, to_user, result_message );

	exec_query( mysql,
		"INSERT INTO pending_remote_broadcast "
		"( user, identity, hash, reqid, seq_num ) "
		"VALUES ( %e, %e, %e, %e, %L )",
		to_user, author_id, author_hash, result_message, seq_num );

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
			"SELECT put_relid FROM friend_claim WHERE user = %e AND friend_id = %e",
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
		const char *friend_id, const char *reqid, long long generation, const char *sym )
{
	message("return_remote_broadcast\n");

	u_char reqid_final[REQID_SIZE];
	RAND_bytes( reqid_final, REQID_SIZE );
	const char *reqid_final_str = bin_to_base64( reqid_final, REQID_SIZE );

	DbQuery recipient( mysql, 
		"UPDATE pending_remote_broadcast "
		"SET generation = %L, sym = %e, reqid_final = %e"
		"WHERE user = %e AND identity = %e AND reqid = %e ",
		generation, sym, reqid_final_str, user, friend_id, reqid );

	BIO_printf( bioOut, "REQID %s\r\n", reqid_final_str );
}

void remoteBroadcastFinal( MYSQL *mysql, const char *user, const char *reqid )
{
	DbQuery recipient( mysql, 
		"SELECT user, identity, hash, seq_num, generation, sym "
		"FROM pending_remote_broadcast "
		"WHERE user = %e AND reqid_final = %e",
		user, reqid );
	
	if ( recipient.rows() == 1 ) {
		MYSQL_ROW row = recipient.fetchRow();
		const char *user = row[0];
		const char *identity = row[1];
		const char *hash = row[2];
		const char *seq_num = row[3];
		const char *generation = row[4];
		const char *sym = row[5];

		long res = sendRemoteBroadcast( mysql, user, hash, 
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

int friendProof( MYSQL *mysql, const char *user, const char *friend_id,
		const char *hash, long long generation, const char *sym )
{
	message("calling remote broadcast from friend_proof\n");
	remote_broadcast( mysql, user, friend_id, hash, generation, sym, strlen(sym) );
	BIO_printf( bioOut, "OK\r\n" );
	return 0;
}

int obtainFriendProof( MYSQL *mysql, const char *user, const char *friendId )
{
	message("obtaining friend proof\n");

	DbQuery friendClaim( mysql, 
		"SELECT id, friend_hash, put_relid FROM friend_claim "
		"WHERE user = %e AND friend_id = %e",
		user, friendId );

	if ( friendClaim.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}
	MYSQL_ROW row = friendClaim.fetchRow();
	long long friendClaimId = strtoll(row[0], 0, 10);
	const char *friendHash = row[1];
	const char *putRelid = row[2];

	char *result = 0;
	sendMessageNow( mysql, false, user, friendId, putRelid, "friend_proof_request\r\n", &result );

	message( "send_message_now returned: %s\n", result );
	EncryptedBroadcastParser ebp;
	if ( ebp.parse( result ) == 0 )
		message( "ebp: %lld %s\n", ebp.generation, ebp.sym.data );
	
	DbQuery update( mysql,
		"UPDATE get_broadcast_key "
		"SET friend_proof = %e "
		"WHERE friend_claim_id = %L and generation = %L",
		ebp.sym.data, friendClaimId, ebp.generation );

	long res = sendRemoteBroadcast( mysql, user, friendHash, 
			ebp.generation, 20, ebp.sym.data );
	if ( res < 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}

	/* FIXME: need to finish friend_proof. */

	DbQuery allProofs( mysql,
		"SELECT friend_hash, generation, friend_proof "
		"FROM friend_claim "
		"JOIN get_broadcast_key ON friend_claim.id = get_broadcast_key.friend_claim_id "
		"WHERE user = %e ",
		user );
	
	for ( int r = 0; r < allProofs.rows(); r++ ) {
		MYSQL_ROW row = allProofs.fetchRow();
		if ( row[1] != 0 && row[2] != 0 ) {
			String msg( "friend_proof %s %s %s\r\n", row[0], row[1], row[2] );
			message("trying to send %s\n", msg.data );
			queueMessage( mysql, user, friendId, msg.data );
		}
	}

	BIO_printf( bioOut, "OK\r\n" );
	
	return 0;
}
