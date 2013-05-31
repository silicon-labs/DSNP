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

#define __STDC_LIMIT_MACROS 1

#include "dsnp.h"
#include "encrypt.h"
#include "lstring.h"
#include "keyagent.h"
#include "error.h"

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

void Server::queueMessage( User &user, const String &iduri, const String &putRelid, const String &msg )
{
	Identity identity( mysql, iduri );

	fetchPublicKey( identity );
	String encPacket = keyAgent.signEncrypt( identity, user, msg );

	DbQuery( mysql,
		"INSERT INTO message_queue "
		"( host, relid, send_after, message ) "
		"VALUES ( %e, %e, NOW(), %d ) ",
		identity.host(), putRelid(), encPacket.binary(), encPacket.length );
}

void Server::queueFofMessage( long long bkId, const String &relid, FriendClaim &friendClaim,
		Identity &recipient, const String &msg )
{
	DbQuery( mysql,
		"INSERT INTO fetch_rb_key_queue "
		"( get_broadcast_key_id, friend_claim_id, actor_identity_id, host, relid, send_after, message ) "
		"VALUES ( %L, %L, %L, %e, %e, NOW(), %d ) ",
		bkId, friendClaim.id, recipient.id(), recipient.host(),
		relid(), msg.binary(), msg.length );
}

bool Server::sendMessage()
{
	MYSQL *mysql = dbConnect();

	/* Try to find a message. */
	DbQuery findOne( mysql, 
		"SELECT id, host, relid, message "
		"FROM message_queue "
		"WHERE now() >= send_after "
		"ORDER BY message_queue.id LIMIT 1"
	);

	if ( findOne.rows() == 0 ) {
		mysql_close( mysql );
		return false;
	}

	MYSQL_ROW row = findOne.fetchRow();
	u_long *lengths = findOne.fetchLengths();

	long long id = parseId( row[0] );
	String host = Pointer( row[1], lengths[1] );
	String relid = Pointer( row[2], lengths[2] );
	String msg = Pointer( row[3], lengths[3] );

	/* Remove it. If removing fails then we assume that some other process
	 * removed the item. */
	DbQuery remove( mysql, 
		"DELETE FROM message_queue "
		"WHERE id = %L", id
	);
	int affected = remove.affectedRows();
	mysql_close( mysql );

	if ( affected == 1 ) {
		message("delivering message %lld with relid %s to %s\n", id, relid(), host() );

		try {
			String result = sendMessageNet( host, relid, msg );
		}
		catch ( UserError &e ) {
			/* Put it back. */
			MYSQL *mysql = dbConnect();

			BioWrap bioWrap( BioWrap::Null );
			e.print( bioWrap );
			message( "error delivering %lld, putting back\n", id );

			DbQuery( mysql,
				"INSERT INTO message_queue "
				"( host, relid, send_after, message ) "
				"VALUES ( %e, %e, DATE_ADD( NOW(), INTERVAL 5 MINUTE ), %d ) ",
				host(), relid(), msg.binary(), msg.length );

			mysql_close( mysql );
		}
	}

	return true;
}

void Server::processFofMessageResult( long long getBroadcastKeyId, 
		long long friendClaimId, long long actorIdentityId, const String &result )
{
	MYSQL *mysql = dbConnect();

	/* Find the friend claim. */
	DbQuery friendClaimQuery( mysql, 
		"SELECT user_id "
		"FROM friend_claim "
		"WHERE id = %L", friendClaimId
	);
	
	if ( friendClaimQuery.rows() == 0 ) 
		return;

	MYSQL_ROW row = friendClaimQuery.fetchRow();
	long long userId = parseId( row[0] );

	User user( mysql, userId );
	Identity senderId( mysql, actorIdentityId );

	String decResult = keyAgent.decryptVerify( senderId, user, result  );

	String hash = sha1( decResult );

	DbQuery( mysql,
		"INSERT IGNORE INTO rb_key "
		"( friend_claim_id, actor_identity_id, hash ) "
		"VALUES ( %L, %L, %e )",
		friendClaimId, actorIdentityId, hash() );
	
	keyAgent.storeRbKey( getBroadcastKeyId, actorIdentityId, hash, decResult );

	/* FIXME: mark only the messages we need to mark. */
	DbQuery( mysql, "UPDATE received_broadcast SET reprocess = true" );

	mysql_close( mysql );
}

bool Server::sendFofMessage()
{
	MYSQL *mysql = dbConnect();

	/* Try to find a message. */
	DbQuery findOne( mysql, 
		"SELECT id, get_broadcast_key_id, friend_claim_id, "
		"	actor_identity_id, host, relid, message "
		"FROM fetch_rb_key_queue "
		"WHERE now() >= send_after ORDER by id LIMIT 1"
	);

	if ( findOne.rows() == 0 ) {
		mysql_close( mysql );
		return false;
	}

	MYSQL_ROW row = findOne.fetchRow();
	u_long *lengths = findOne.fetchLengths();

	long long id = parseId( row[0] );
	long long getBroadcastKeyId = parseId( row[1] );
	long long friendClaimId = parseId( row[2] );
	long long actorIdentityId = parseId( row[3] );
	String host = Pointer( row[4], lengths[4] );
	String relid = Pointer( row[5], lengths[5] );
	String msg = Pointer( row[6], lengths[6] );

	/* Remove it. If removing fails then we assume that some other process
	 * removed the item. */
	DbQuery remove( mysql, 
		"DELETE FROM fetch_rb_key_queue "
		"WHERE id = %L", id
	);
	int affected = remove.affectedRows();
	mysql_close( mysql );

	if ( affected == 1 ) {
		message("delivering fof_message %lld\n", id );

		try {
			String result = sendFofMessageNet( host, relid, msg );
			processFofMessageResult( getBroadcastKeyId, friendClaimId, actorIdentityId, result );
		}
		catch ( UserError &e ) {
			/* Put it back. */
			MYSQL *mysql = dbConnect();

			BioWrap bioWrap( BioWrap::Null );
			e.print( bioWrap );
			message( "error delivering %lld, putting back\n", id );

			DbQuery( mysql,
				"INSERT INTO fetch_rb_key_queue "
				"( friend_claim_id, actor_identity_id, host, relid, send_after, message ) "
				"VALUES ( %L, %L, %e, %e, DATE_ADD( NOW(), INTERVAL 5 MINUTE ), %d ) ",
				friendClaimId, actorIdentityId, host(), relid(), msg.binary(), msg.length );

			mysql_close( mysql );
		}
	}

	return true;
}


long storeBroadcastRecipients( MYSQL *mysql, User &user,
	long long messageId, DbQuery &recipients )
{
	String lastHost;
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
		String host = Pointer( identity.host() );
		if ( lastHost.length == 0 || lastHost != host ) {
			DbQuery( mysql,
				"INSERT INTO broadcast_queue "
				"( broadcast_message_id, host, send_after ) "
				"VALUES ( %L, %e, NOW() ) ",
				messageId, host() );

			lastQueueId = lastInsertId( mysql );
			lastHost.set( host );
		}

		/* Insert the recipient. */
		DbQuery( mysql,
			"INSERT INTO broadcast_recipient "
			"( broadcast_queue_id, relid ) "
			"VALUES ( %L, %e ) ",
			lastQueueId, putRelid );

		count += 1;
	}
	return count;
}

void Server::queueBroadcast( User &user, String &msg )
{
	/* Get the latest put session key. */
	long long networkId = findPrimaryNetworkId( mysql, user );
	PutKey put( mysql, networkId );

	/* Do the encryption. */ 
	String encPacket = keyAgent.bkEncrypt( put.id, msg ); 

	/* Store the message. */
	DbQuery( mysql,
		"INSERT INTO broadcast_message "
		"( dist_name, key_gen, message ) "
		"VALUES ( %e, %L, %d ) ",
		put.distName(), put.generation,
		encPacket.binary(), encPacket.length );

	long long messageId = lastInsertId( mysql );

	/*
	 * Recipients.
	 */
	DbQuery outOfTree( mysql,
		"SELECT identity.id, identity.iduri, put_relid.put_relid "
		"FROM friend_claim "
		"JOIN put_relid ON friend_claim.id = put_relid.friend_claim_id "
		"JOIN identity ON friend_claim.identity_id = identity.id "
		"JOIN network_member "
		"ON friend_claim.id = network_member.friend_claim_id "
		"WHERE friend_claim.user_id = %L AND friend_claim.state = %l AND"
		"	network_member.network_id = %L AND put_relid.key_priv = %l",
		user.id(), FC_ESTABLISHED, networkId, KEY_PRIV3 );

	storeBroadcastRecipients( mysql, user, messageId, outOfTree );
}

bool Server::sendBroadcastMessage()
{
	MYSQL *mysql = dbConnect();

	/* Try to find a message. */
	DbQuery queue( mysql, 
		"SELECT id, broadcast_message_id, host "
		"FROM broadcast_queue "
		"WHERE now() >= send_after ORDER by id LIMIT 1"
	);

	if ( queue.rows() == 0 ) {
		mysql_close( mysql );
		return false;
	}

	MYSQL_ROW row = queue.fetchRow();
	u_long *lengths = queue.fetchLengths();
	long long queueId = parseId( row[0] );
	long long messageId = parseId( row[1] );
	String host = Pointer( row[2], lengths[2] );

	/* Remove it. */
	DbQuery remove( mysql, 
		"DELETE FROM broadcast_queue WHERE id = %L", 
		queueId );
	int affected = remove.affectedRows();

	message( "processing queue %lld with message %lld\n", queueId, messageId );

	/* If we were not able to remove it, then someone other process removed it
	 * and now has repsonsibility for it. */
	if ( affected == 0 ) {
		mysql_close( mysql );
		return true;
	}
		
	DbQuery findMsg( mysql, 
		"SELECT dist_name, key_gen, message "
		"FROM broadcast_message "
		"WHERE id = %L ",
		messageId
	);

	if ( findMsg.rows() != 1 ) {
		error("broadcast message %lld not found, message lost\n");
		mysql_close( mysql );
		return true;
	}

	row = findMsg.fetchRow();
	lengths = findMsg.fetchLengths();
	const char *group = row[0];
	long long keyGen = parseId( row[1] );
	String msg = Pointer( row[2], lengths[2] );

	DbQuery recipients( mysql,
		"SELECT relid "
		"FROM broadcast_recipient "
		"WHERE broadcast_queue_id = %L ",
		queueId );

	/* Free the connection. */
	mysql_close( mysql );

	message( "there are %d recipients\n", recipients.rows() );
	RecipientList recipientList;
	
	while ( true ) {
		row = recipients.fetchRow();
		if ( !row )
			break;
		const char *relid = row[0];
		recipientList.push_back( std::string(relid) );
		message( "sending %lld to %s %s\n", queueId, host(), relid );
	}

	/* If failed. */
	try {
		String network = Pointer( group );
		sendBroadcastNet( host, recipientList, network, keyGen, msg );
	}
	catch ( UserError &e ) {
		MYSQL *mysql = dbConnect();

		BioWrap bioWrap( BioWrap::Null );
		e.print( bioWrap );
		message( "error delivering %lld, putting back\n", queueId );

		DbQuery( mysql,
			"INSERT INTO broadcast_queue "
			"( broadcast_message_id, host, send_after ) "
			"VALUES ( %L, %e, DATE_ADD( NOW(), INTERVAL 5 MINUTE ) ) ",
			messageId, host() );

		long long newQueueId = lastInsertId( mysql );

		DbQuery( mysql,
			"UPDATE broadcast_recipient "
			"SET broadcast_queue_id = %L "
			"WHERE broadcast_queue_id = %L ",
			newQueueId, queueId );

		mysql_close( mysql );
	}

	return true;
}


long Server::runBroadcastQueue()
{
	while ( true ) {
		bool itemsLeft = sendBroadcastMessage();
		if ( !itemsLeft )
			break;
	}
	return 0;
}

long Server::runMessageQueue()
{
	while ( true ) {
		bool itemsLeft = sendMessage();
		if ( !itemsLeft )
			break;
	}
	return 0;
}

long Server::runFofMessageQueue()
{
	while ( true ) {
		bool itemsLeft = sendFofMessage();
		if ( !itemsLeft )
			break;
	}
	return 0;
}

bool checkDeliveryQueues( MYSQL *mysql )
{
	/* Try to find a message. */
	DbQuery check1( mysql, 
		"SELECT id "
		"FROM broadcast_queue "
		"WHERE now() >= send_after ORDER by id LIMIT 1"
	);

	if ( check1.rows() > 0 )
		return true;

	/* Try to find a message. */
	DbQuery check2( mysql, 
		"SELECT id "
		"FROM message_queue "
		"WHERE now() >= send_after ORDER by message_queue.id LIMIT 1"
	);

	if ( check2.rows() > 0 )
		return true;

	/* Try to find a message. */
	DbQuery check3( mysql, 
		"SELECT id "
		"FROM fetch_rb_key_queue "
		"WHERE now() >= send_after ORDER by id LIMIT 1"
	);

	if ( check3.rows() > 0 )
		return true;

	return false;
}

uint64_t nextDelivery( MYSQL *mysql )
{
	uint64_t next = UINT64_MAX;

	DbQuery check1( mysql, 
		"SELECT UNIX_TIMESTAMP( send_after ) "
		"FROM broadcast_queue "
		"ORDER BY id LIMIT 1"
	);

	if ( check1.rows() > 0 ) {
		uint64_t nextBq = strtoull( check1.fetchRow()[0], 0, 10 );
		if ( nextBq < next )
			next = nextBq;
	}

	/* Try to find a message. */
	DbQuery check2( mysql, 
		"SELECT UNIX_TIMESTAMP( send_after ) "
		"FROM message_queue "
		"ORDER BY id LIMIT 1"
	);

	if ( check2.rows() > 0 ) {
		uint64_t nextBq = strtoull( check2.fetchRow()[0], 0, 10 );
		if ( nextBq < next )
			next = nextBq;
	}

	/* Try to find a message. */
	DbQuery check3( mysql, 
		"SELECT UNIX_TIMESTAMP( send_after ) "
		"FROM fetch_rb_key_queue "
		"ORDER BY id LIMIT 1"
	);

	if ( check3.rows() > 0 ) {
		uint64_t nextBq = strtoull( check3.fetchRow()[0], 0, 10 );
		if ( nextBq < next )
			next = nextBq;
	}

	return next;
}

bool checkStateChange( MYSQL *mysql )
{
	/* Try to find a message. */
	DbQuery check( mysql, 
		"SELECT id, relid, dist_name, generation, message "
		"FROM received_broadcast "
		"WHERE reprocess ORDER by id LIMIT 1"
	);

	if ( check.rows() > 0 ) 
		return true;

	return false;
}

