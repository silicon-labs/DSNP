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
	appNotification( args, msg, length );
}

void receiveMessage( MYSQL *mysql, const char *relid, const char *msg )
{
	exec_query( mysql, 
		"SELECT id, user, friend_id, friend_hash FROM friend_claim "
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
	const char *friendId = row[2];
	const char *friendHash = row[3];

	RSA *user_priv = load_key( mysql, user );
	RSA *id_pub = fetch_public_key( mysql, friendId );

	Encrypt encrypt( id_pub, user_priv );
	int decryptRes = encrypt.decryptVerify( msg );

	if ( decryptRes < 0 ) {
		message("message receipt: decryption failed\n" );
		BIO_printf( bioOut, "ERROR %s\r\n", encrypt.err );
		return;
	}

	message("received message: %.*s\n", (int)encrypt.decLen, (char*)encrypt.decrypted );

	MessageParser mp;
	mp.parse( (char*)encrypt.decrypted, encrypt.decLen );
	switch ( mp.type ) {
		case MessageParser::BroadcastKey:
			storeBroadcastKey( mysql, id, user, friendId, friendHash,
					mp.group, mp.generation, mp.key, mp.sym );
			break;
		case MessageParser::ForwardTo: 
			forwardTo( mysql, id, user, friendId, mp.number,
					mp.generation, mp.identity, mp.relid );
			break;
		case MessageParser::EncryptRemoteBroadcast: 
			encryptRemoteBroadcast( mysql, user, friendId, mp.token,
					mp.seq_num, mp.group, mp.embeddedMsg, mp.length );
			break;
		case MessageParser::ReturnRemoteBroadcast:
			return_remote_broadcast( mysql, user, friendId, mp.reqid,
					mp.generation, mp.sym );
			break;
		case MessageParser::FriendProof:
			friendProofMessage( mysql, user, friendId, mp.hash, mp.group, mp.generation, mp.sym );
			break;
		case MessageParser::UserMessage:
			userMessage( mysql, user, friendId, mp.date, mp.embeddedMsg, mp.length );
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
	String command( "user_message %s %ld\r\n", timeStr.data, mLen );
	String full = addMessageData( command, msg, mLen );

	long sendResult = queueMessage( mysql, user, toIdentity, full.data, full.length );
	if ( sendResult < 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}

	BIO_printf( bioOut, "OK\r\n" );
	return 0;
}

