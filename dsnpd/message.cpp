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

void userMessage( MYSQL *mysql, const char *user, const char *friendId,
		const char *date, const char *msg, long length )
{
	String args( "user_message %s - %s 0 %s %ld", 
			user, friendId, date, length );
	app_notification( args, msg, length );
}

void receiveMessage( MYSQL *mysql, const char *relid, const char *msg )
{
	message("received message\n");

	exec_query( mysql, 
		"SELECT id, user, friend_id FROM friend_claim "
		"WHERE get_relid = %e",
		relid );

	MYSQL_RES *result = mysql_store_result( mysql );
	MYSQL_ROW row = mysql_fetch_row( result );
	if ( row == 0 ) {
		message("message receipt: no friend claim for %s\n", relid );
		BIO_printf( bioOut, "ERROR finding friend\r\n" );
		return;
	}
	long long id = strtoll(row[0], 0, 10);
	const char *user = row[1];
	const char *friend_id = row[2];

	RSA *user_priv = load_key( mysql, user );
	RSA *id_pub = fetch_public_key( mysql, friend_id );

	Encrypt encrypt( id_pub, user_priv );
	int decryptRes = encrypt.decryptVerify( msg );

	if ( decryptRes < 0 ) {
		message("message receipt: decryption failed\n" );
		BIO_printf( bioOut, "ERROR %s\r\n", encrypt.err );
		return;
	}

	MessageParser mp;
	mp.parse( (char*)encrypt.decrypted, encrypt.decLen );
	switch ( mp.type ) {
		case MessageParser::BroadcastKey:
			storeBroadcastKey( mysql, id, mp.group, mp.generation, mp.key, mp.sym );
			break;
		case MessageParser::ForwardTo: 
			forwardTo( mysql, id, user, friend_id, mp.number,
					mp.generation, mp.identity, mp.relid );
			break;
		case MessageParser::EncryptRemoteBroadcast: 
			encrypt_remote_broadcast( mysql, user, friend_id, mp.token,
					mp.seq_num, mp.containedMsg );
			break;
		case MessageParser::ReturnRemoteBroadcast:
			return_remote_broadcast( mysql, user, friend_id, mp.reqid,
					mp.generation, mp.sym );
			break;
		case MessageParser::FriendProofRequest:
			friendProofRequest( mysql, user, friend_id );
			break;
		case MessageParser::FriendProof:
			friendProof( mysql, user, friend_id, mp.hash, mp.generation, mp.sym );
			break;
		case MessageParser::UserMessage:
			userMessage( mysql, user, friend_id, mp.date, mp.containedMsg, mp.length );
			break;
		default:
			BIO_printf( bioOut, "ERROR\r\n" );
			break;
	}
}

long submitMessage( MYSQL *mysql, const char *user, const char *toIdentity, const char *msg, long mLen )
{
	String timeStr = timeNow();

	/* Make the full message. */
	String messageCmd( "user_message %s %ld\r\n", timeStr.data, mLen );
	char *full = new char[messageCmd.length + mLen + 2];
	memcpy( full, messageCmd.data, messageCmd.length );
	memcpy( full + messageCmd.length, msg, mLen );
	memcpy( full + messageCmd.length + mLen, "\r\n", 2 );

	long sendResult = queueMessage( mysql, user, toIdentity, full );
	if ( sendResult < 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}

	BIO_printf( bioOut, "OK\r\n" );
	return 0;
}

