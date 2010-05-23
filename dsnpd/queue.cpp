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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

bool sendBroadcastMessage()
{
	MYSQL *mysql = dbConnect();

	/* Try to find a message. */
	DbQuery queue( mysql, 
		"SELECT id, message_id, to_site, forward "
		"FROM broadcast_queue "
		"WHERE now() >= send_after ORDER by id LIMIT 1"
	);

	if ( queue.rows() == 0 )
		return false;

	MYSQL_ROW row = queue.fetchRow();
	long long queueId = strtoll( row[0], 0, 10 );
	long long messageId = strtoll( row[1], 0, 10 );
	char *toSite = row[2];
	int forward = atoi( row[3] );

	/* Remove it. */
	DbQuery remove( mysql, "DELETE FROM broadcast_queue WHERE id = %L", queueId );
	int affected = remove.affectedRows();

	message( "processing queue %lld with message %lld\n", queueId, messageId );

	/* If we were not able to remove it, then someone other process removed it now
	 * has repsonsibility for it. */
	if ( affected == 0 ) {
		mysql_close( mysql );
		return true;
	}
		
	DbQuery findMsg( mysql, 
		"SELECT network_name, key_gen, tree_gen_low, tree_gen_high, message "
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
	const char *group = row[0];
	long long keyGen = strtoll( row[1], 0, 10 );
	long long treeGenLow = strtoll( row[2], 0, 10 );
	long long treeGenHigh = strtoll( row[3], 0, 10 );
	char *msg = row[4];

	DbQuery recipients( mysql,
		"SELECT relid "
		"FROM broadcast_recipient "
		"WHERE queue_id = %L ",
		queueId );

	/* Free the connection. */
	mysql_close( mysql );

	message( "there are %d recipients\n", recipients.rows() );
	RecipientList recipientList;
	
	while ( true ) {
		row = recipients.fetchRow();
		if ( !row )
			break;
		const char *toRelid = row[0];
		recipientList.push_back( std::string(toRelid) );
		message( "sending %lld to %s %s\n", queueId, toSite, toRelid );
	}


	/* If failed. */
	long sendRes = sendBroadcastNet( mysql, toSite, recipientList, group,
			keyGen, forward, treeGenLow, treeGenHigh, msg, strlen(msg) );

	if ( sendRes < 0 ) {
		MYSQL *mysql = dbConnect();

		DbQuery( mysql,
			"INSERT INTO broadcast_queue "
			"( message_id, send_after, to_site, forward ) "
			"VALUES ( %L, DATE_ADD( NOW(), INTERVAL 10 MINUTE ), %e, %b ) ",
			messageId, toSite, forward );

		long long newQueueId = lastInsertId( mysql );

		DbQuery( mysql,
			"UPDATE broadcast_recipient "
			"SET queue_id = %L "
			"WHERE queue_id = %L ",
			newQueueId, queueId );

		mysql_close( mysql );
	}

	return true;
}

long queueMessageDb( MYSQL *mysql, const char *from_user,
		const char *to_identity, const char *relid, const char *msg )
{
	DbQuery( mysql,
		"INSERT INTO message_queue "
		"( from_user, to_id, relid, message, send_after ) "
		"VALUES ( %e, %e, %e, %e, NOW() ) ",
		from_user, to_identity, relid, msg );

	/* Get the id that was assigned to the message. */
	DbQuery lastId( mysql, "SELECT LAST_INSERT_ID()" );
	if ( lastId.rows() > 0 ) {
		MYSQL_ROW row = lastId.fetchRow();
		message( "queued message %s from %s to %s\n", row[0], from_user, to_identity );
	}

	return 0;
}

long queueMessage( MYSQL *mysql, const char *from_user,
		const char *to_identity, const char *msg, long mLen )
{
	DbQuery claim( mysql, 
		"SELECT put_relid FROM friend_claim "
		"WHERE user = %e AND friend_id = %e ",
		from_user, to_identity );

	if ( claim.rows() == 0 )
		return -1;

	MYSQL_ROW row = claim.fetchRow();
	const char *relid = row[0];

	RSA *id_pub = fetchPublicKey( mysql, to_identity );
	RSA *user_priv = load_key( mysql, from_user );

	Encrypt encrypt( id_pub, user_priv );

	encrypt.signEncrypt( (u_char*)msg, mLen );
	queueMessageDb( mysql, from_user, to_identity, relid, encrypt.sym );
	return 0;
}

bool sendMessage()
{
	MYSQL *mysql = dbConnect();

	/* Try to find a message. */
	DbQuery findOne( mysql, 
		"SELECT id, from_user, to_id, relid, message "
		"FROM message_queue "
		"WHERE now() >= send_after ORDER by id LIMIT 1"
	);

	if ( findOne.rows() == 0 )
		return false;

	MYSQL_ROW row = findOne.fetchRow();

	long long id = strtoll( row[0], 0, 10 );

	char *from_user = row[1];
	char *to_id = row[2];
	char *relid = row[3];
	char *msg = row[4];
	
	/* Remove it. If removing fails then we assume that some other process
	 * removed the item. */
	DbQuery remove( mysql, 
		"DELETE FROM message_queue "
		"WHERE id = %L",
		id
	);
	int affected = remove.affectedRows();
	mysql_close( mysql );

	if ( affected == 1 ) {
		message("delivering message %lld from %s to %s\n", id, from_user, to_id );

		long send_res = sendMessageNet( mysql, false, from_user, to_id, relid, 
				msg, strlen(msg), 0 );

		if ( send_res < 0 ) {
			error( "trouble sending message: %ld\n", send_res );

			MYSQL *mysql = dbConnect();

			/* Queue the message. */
			DbQuery( mysql,
					"INSERT INTO message_queue "
					"( from_user, to_id, relid, message, send_after ) "
					"VALUES ( %e, %e, %e, %e, DATE_ADD( NOW(), INTERVAL 10 MINUTE ) ) ",
					from_user, to_id, relid, msg );

			mysql_close( mysql );
		}
	}

	return true;
}

long runBroadcastQueue()
{
	while ( true ) {
		bool itemsLeft = sendBroadcastMessage();
		if ( !itemsLeft )
			break;
	}
	return 0;
}

long runMessageQueue()
{
	while ( true ) {
		bool itemsLeft = sendMessage();
		if ( !itemsLeft )
			break;
	}
	return 0;
}

void runQueue( const char *siteName )
{
	setConfigByName( siteName );
	if ( c != 0 ) {
		runBroadcastQueue();
		runMessageQueue();
	}
}

