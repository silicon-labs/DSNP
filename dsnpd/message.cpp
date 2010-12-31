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

void userMessage( MYSQL *mysql, const char *user, const char *friendId,
		const char *date, const char *msg, long length )
{
	String args( "notification_message %s %s %s %ld", 
			user, friendId, date, length );
	appNotification( args, msg, length );
}

void addGetBroadcastKey( MYSQL *mysql, long long friendClaimId, long long networkId, long long generation )
{
	DbQuery check( mysql,
		"INSERT IGNORE INTO get_broadcast_key ( friend_claim_id, network_id, generation ) "
		"VALUES ( %L, %L, %L )",
		friendClaimId, networkId, generation );
}

void storeBroadcastKey( MYSQL *mysql, long long friendClaimId, const char *user, long long userId,
		const char *friendId, const char *friendHash, const char *network,
		long long generation, const char *broadcastKey, const char *friendProof1, 
		const char *friendProof2 )
{
	/* Make sure we have the network for the user. */
	long long networkId = addNetwork( mysql, userId, network );

	/* Store the key. */
	addGetBroadcastKey( mysql, friendClaimId, networkId, generation );
	DbQuery( mysql, 
			"UPDATE get_broadcast_key "
			"SET broadcast_key = %e, friend_proof = %e, reverse_proof = %e "
			"WHERE friend_claim_id = %L AND network_id = %L AND generation = %L",
			broadcastKey, friendProof1, friendProof2, friendClaimId, networkId, generation );

	if ( friendProof1 != 0 ) {
		/* Broadcast the friend proof that we just received. */
		message( "broadcasting in-proof for user %s network %s <- %s\n", user, network, friendId );
		sendRemoteBroadcast( mysql, user, friendHash, network, generation, 20, friendProof1 );
	}

	if ( friendProof2 != 0 ) {
		/* If we have them in this group then broadcast the reverse as well. */
		DbQuery haveReverse( mysql,
			"SELECT id FROM network_member "
			"WHERE network_id = %L AND friend_claim_id = %L",
			networkId, friendClaimId );

		if ( haveReverse.rows() ) {
			/* Sending friend */
			message( "broadcasting out-proof for user %s network %s -> %s\n", user, network, friendId );
			sendRemoteBroadcast( mysql, user, friendHash, network, generation, 20, friendProof2 );
		}
	}

	BIO_printf( bioOut, "OK\n" );
}

int friendProofMessage( MYSQL *mysql, const char *user, long long userId, const char *friend_id,
		const char *hash, const char *network, long long generation, const char *sym )
{
	message("calling remote broadcast from friend proof symLen %d sym %s\n", strlen(sym), sym );

	long long networkId = addNetwork( mysql, userId, network );

	remoteBroadcast( mysql, user, friend_id, hash, network, networkId, generation, sym, strlen(sym) );
	BIO_printf( bioOut, "OK\r\n" );
	return 0;
}


void receiveMessage( MYSQL *mysql, const char *relid, const char *msg )
{
	DbQuery claim( mysql, 
		"SELECT friend_claim.id, friend_claim.user, friend_claim.iduri, "
		"	friend_claim.friend_hash, user.id "
		"FROM friend_claim "
		"JOIN user ON friend_claim.user = user.user "
		"WHERE get_relid = %e",
		relid );

	if ( claim.rows() == 0 ) {
		message("message receipt: no friend claim for %s\n", relid );
		BIO_printf( bioOut, "ERROR finding friend\r\n" );
		return;
	}
	MYSQL_ROW row = claim.fetchRow();
	long long id = strtoll(row[0], 0, 10);
	const char *user = row[1];
	const char *friendId = row[2];
	const char *friendHash = row[3];
	long long userId = strtoll(row[4], 0, 10);

	Keys *user_priv = loadKey( mysql, user );
	Keys *id_pub = fetchPublicKey( mysql, friendId );

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
			storeBroadcastKey( mysql, id, user, userId, friendId, friendHash,
					mp.network, mp.generation, mp.key, 0, 0 );
			break;
		case MessageParser::BkProof:
			storeBroadcastKey( mysql, id, user, userId, friendId, friendHash,
					mp.network, mp.generation, mp.key, mp.sym1, mp.sym2 );
			break;
		case MessageParser::EncryptRemoteBroadcast: 
			encryptRemoteBroadcast( mysql, user, friendId, mp.token,
					mp.seq_num, mp.network, mp.embeddedMsg, mp.length );
			break;
		case MessageParser::ReturnRemoteBroadcast:
			return_remote_broadcast( mysql, user, friendId, mp.reqid,
					mp.generation, mp.sym );
			break;
		case MessageParser::FriendProof:
			friendProofMessage( mysql, user, userId, friendId, mp.hash,
					mp.network, mp.generation, mp.sym );
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

