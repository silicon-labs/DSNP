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

#include "dsnpd.h"
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
}

void remote_broadcast( MYSQL *mysql, const char *relid, const char *user, const char *friend_id, 
		const char *hash, long long generation, const char *msg, long mLen )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	char *broadcast_key, *author_id;
	RSA *id_pub;
	Encrypt encrypt;
	int decryptRes;

	message( "remote_broadcast, generation: %lld\n", generation );

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

	message("dispatching broadcast_parser\n");
//	parseRes = broadcast_parser( seq_num, mysql, relid, user, friend_id, decrypted, decLen );
//	if ( parseRes < 0 )
//		message("broadcast_parser failed\n");

	BroadcastParser bp;
	parseRes = bp.parse( decrypted, decLen );
	if ( parseRes < 0 )
		message("broadcast_parser failed\n");
	else {
		switch ( bp.type ) {
			case BroadcastParser::Direct:
				direct_broadcast( mysql, relid, user, friend_id, bp.seq_num, 
						bp.date, bp.embeddedMsg, bp.length );
				break;
			case BroadcastParser::Remote:
				remote_broadcast( mysql, relid, user, friend_id, bp.hash, 
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

