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
	MYSQL_RES *result;
	MYSQL_ROW row;
	char *broadcast_key, *author_id;
	RSA *id_pub;
	Encrypt encrypt;
	int decryptRes;

	message( "remote_broadcast: user %s hash %s generation %lld\n", user, hash, generation );

	/* Messages has a remote sender and needs to be futher decrypted. */
	exec_query( mysql, 
		"SELECT friend_claim.friend_id, get_tree.broadcast_key "
		"FROM friend_claim "
		"JOIN get_tree "
		"ON friend_claim.user = get_tree.user AND "
		"	friend_claim.friend_id = get_tree.friend_id "
		"WHERE friend_claim.user = %e AND friend_claim.friend_hash = %e AND "
		"	get_tree.generation <= %L "
		"ORDER BY get_tree.generation DESC LIMIT 1",
		user, hash, generation );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row ) {
		author_id = row[0];
		broadcast_key = row[1];

		/* Do the decryption. */
		id_pub = fetch_public_key( mysql, author_id );
		encrypt.load( id_pub, 0 );
		decryptRes = encrypt.bkDecryptVerify( broadcast_key, msg );

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
		}
	}
}


void broadcast( MYSQL *mysql, const char *relid, long long generation, const char *encrypted )
{
	char *user, *friend_id, *broadcast_key;
	char *relid_ret;
	char *site1, *relid1;
	char *site2, *relid2;
	RSA *id_pub;
	Encrypt encrypt;
	int decryptRes, parseRes, decLen;
	char *decrypted;

	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT friend_claim.user, friend_claim.friend_id, "
		"	get_tree.relid_ret, "
		"	get_tree.site1, get_tree.relid1, "
		"	get_tree.site2, get_tree.relid2, "
		"	get_tree.broadcast_key "
		"FROM friend_claim JOIN get_tree "
		"ON friend_claim.user = get_tree.user AND "
		"	friend_claim.friend_id = get_tree.friend_id "
		"WHERE friend_claim.get_relid = %e AND get_tree.generation <= %L "
		"ORDER BY get_tree.generation DESC LIMIT 1",
		relid, generation );
	
	if ( recipient.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR bad recipient\r\n");
		return;
	}

	MYSQL_ROW row = recipient.fetchRow();
	user = row[0];
	friend_id = row[1];
	relid_ret = row[2];
	site1 = row[3];
	relid1 = row[4];
	site2 = row[5];
	relid2 = row[6];
	broadcast_key = row[7];

	/* Do the decryption. */
	id_pub = fetch_public_key( mysql, friend_id );
	encrypt.load( id_pub, 0 );
	decryptRes = encrypt.bkDecryptVerify( broadcast_key, encrypted );

	if ( decryptRes < 0 ) {
		message("bkDecryptVerify failed\n");
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}

	/* Take a copy of the decrypted message. */
	decrypted = new char[encrypt.decLen+1];
	memcpy( decrypted, encrypt.decrypted, encrypt.decLen );
	decrypted[encrypt.decLen] = 0;
	decLen = encrypt.decLen;

	BroadcastParser bp;
	parseRes = bp.parse( decrypted, decLen );
	if ( parseRes < 0 )
		error("broadcast_parser failed\n");
	else {
		switch ( bp.type ) {
			case BroadcastParser::Direct:
				direct_broadcast( mysql, relid, user, friend_id, bp.seq_num, 
						bp.date, bp.embeddedMsg, bp.length );
				break;
			case BroadcastParser::Remote:
				remote_broadcast( mysql, user, friend_id, bp.hash, 
						bp.generation, bp.embeddedMsg, bp.length );
				break;
		}
	}

	/* 
	 * Now do the forwarding.
	 */

	if ( site1 != 0 )
		queue_broadcast_db( mysql, site1, relid1, generation, encrypted );

	if ( site2 != 0 )
		queue_broadcast_db( mysql, site2, relid2, generation, encrypted );
	
	BIO_printf( bioOut, "OK\r\n" );
}


long queue_broadcast( MYSQL *mysql, const char *user, const char *msg, long mLen )
{
	long long generation;
	String broadcast_key;

	/* Get the latest put session key. */
	currentPutBk( mysql, user, generation, broadcast_key );
	message("queue_broadcast: using %lld %s\n", generation, broadcast_key.data );

	/* Find root friend. */
	DbQuery rootFriend( mysql,
		"SELECT friend_claim.friend_id, friend_claim.put_relid "
		"FROM friend_claim "
		"JOIN put_tree "
		"ON friend_claim.user = put_tree.user AND "
		"	friend_claim.friend_id = put_tree.friend_id "
		"WHERE friend_claim.user = %e AND put_tree.root = true AND"
		"	put_tree.generation <= %L "
		"ORDER BY generation DESC LIMIT 1",
		user, generation );

	if ( rootFriend.rows() == 0 ) {
		/* Nothing here means that the user has no friends (sniff). */
	}
	else {
		MYSQL_ROW row = rootFriend.fetchRow();
		char *friend_id = row[0];
		char *put_relid = row[1];

		message( "queue_broadcast: using root node: %s\n", friend_id );

		/* Do the encryption. */
		RSA *user_priv = load_key( mysql, user );
		Encrypt encrypt( 0, user_priv );
		encrypt.bkSignEncrypt( broadcast_key, (u_char*)msg, mLen );

		/* Find the root user to send to. */
		Identity id( friend_id );
		id.parse();

		queue_broadcast_db( mysql, id.site, put_relid,
				generation, encrypt.sym );
	}

	return 0;
}


long send_broadcast( MYSQL *mysql, const char *user,
		const char *msg, long mLen )
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
	DbQuery lastInsertId( mysql, "SELECT last_insert_id()" );
	if ( lastInsertId.rows() != 1 )
		return -1;

	long long seq_num = strtoll( lastInsertId.fetchRow()[0], 0, 10 );

	/* Make the full message. */
	String broadcastCmd(
		"direct_broadcast %lld %s %ld\r\n",
		seq_num, timeStr.data, mLen );
	char *full = new char[broadcastCmd.length + mLen + 2];
	memcpy( full, broadcastCmd.data, broadcastCmd.length );
	memcpy( full + broadcastCmd.length, msg, mLen );
	memcpy( full + broadcastCmd.length + mLen, "\r\n", 2 );

	long sendResult = queue_broadcast( mysql, user, full, broadcastCmd.length + mLen + 2 );
	if ( sendResult < 0 )
		return -1;

	return 0;
}


long submit_broadcast( MYSQL *mysql, const char *user,
		const char *msg, long mLen )
{
	int result = send_broadcast( mysql, user, msg, mLen );

	if ( result < 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		goto close;
	}

	BIO_printf( bioOut, "OK\r\n" );

close:
	return 0;
}

long send_remote_broadcast( MYSQL *mysql, const char *user, const char *author_id,
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

	long sendResult = queue_broadcast( mysql, user, full.data, full.length );
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

		long res = send_remote_broadcast( mysql, user, identity, 
				hash, strtoll(generation, 0, 10), strtoll(seq_num, 0, 10), sym );
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
	return 0;
}

int obtainFriendProof( MYSQL *mysql, const char *user, const char *friendId )
{
	message("obtaining friend proof\n");

	DbQuery friendClaim( mysql, 
		"SELECT friend_hash, put_relid FROM friend_claim "
		"WHERE user = %e AND friend_id = %e",
		user, friendId );

	if ( friendClaim.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}
	MYSQL_ROW row = friendClaim.fetchRow();
	const char *friendHash = row[0];
	const char *putRelid = row[1];

	char *result = 0;
	sendMessageNow( mysql, false, user, friendId, putRelid, "friend_proof_request\r\n", &result );

	message( "send_message_now returned: %s\n", result );
	EncryptedBroadcastParser ebp;
	if ( ebp.parse( result ) == 0 )
		message( "ebp: %lld %s\n", ebp.generation, ebp.sym.data );
	
	DbQuery update( mysql,
		"UPDATE friend_claim "
		"SET fp_generation = %L, friend_proof = %e "
		"WHERE user = %e AND friend_id = %e",
		ebp.generation, ebp.sym.data, user, friendId );

	long res = send_remote_broadcast( mysql, user, friendId, friendHash, ebp.generation, 20, ebp.sym.data );
	if ( res < 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}

	DbQuery allProofs( mysql,
		"SELECT friend_hash, fp_generation, friend_proof "
		"FROM friend_claim "
		"WHERE user = %e",
		user );
	
	for ( int r = 0; r < allProofs.rows(); r++ ) {
		MYSQL_ROW row = allProofs.fetchRow();
		if ( row[1] != 0 && row[2] != 0 ) {
			String msg( "friend_proof %s %s %s\r\n", row[0], row[1], row[2] );
			message("trying to send %s\n", msg.data );
			queue_message( mysql, user, friendId, msg.data );
		}
	}

	BIO_printf( bioOut, "OK\r\n" );
	
	return 0;
}


