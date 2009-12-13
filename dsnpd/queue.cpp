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

bool send_broadcast_message()
{
	MYSQL *mysql = db_connect();

	/* Try to find a message. */
	DbQuery findOne( mysql, 
		"SELECT id, to_site, relid, generation, message "
		"FROM broadcast_queue "
		"WHERE now() >= send_after ORDER by id LIMIT 1"
	);

	if ( findOne.rows() == 0 )
		return false;

	MYSQL_ROW row = findOne.fetchRow();
	long long id = strtoll( row[0], 0, 10 );
	char *to_site = row[1];
	char *relid = row[2];
	long long generation = strtoll( row[3], 0, 10 );
	char *msg = row[4];
	
	/* Remove it. If removing fails then we assume that some other process
	 * removed the item. */
	DbQuery remove( mysql, 
		"DELETE FROM broadcast_queue "
		"WHERE id = %L",
		id
	);
	int affected = remove.affectedRows();
	mysql_close( mysql );

	if ( affected == 1 ) {
		long send_res = send_broadcast_net( mysql, to_site, relid,
				generation, msg, strlen(msg) );

		if ( send_res < 0 ) {
			error( "trouble sending message: %ld\n", send_res );

			MYSQL *mysql = db_connect();

			/* Queue the message. */
			DbQuery( mysql,
					"INSERT INTO broadcast_queue "
					"( to_site, relid, generation, message, send_after ) "
					"VALUES ( %e, %e, %L, %e, DATE_ADD( NOW(), INTERVAL 10 MINUTE ) ) ",
					to_site, relid, generation, msg );

			mysql_close( mysql );
		}
	}

	return true;
}

long queue_message_db( MYSQL *mysql, const char *from_user,
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

long queue_message( MYSQL *mysql, const char *from_user,
		const char *to_identity, const char *msg )
{
	DbQuery claim( mysql, 
		"SELECT put_relid FROM friend_claim "
		"WHERE user = %e AND friend_id = %e ",
		from_user, to_identity );

	if ( claim.rows() == 0 )
		return -1;

	MYSQL_ROW row = claim.fetchRow();
	const char *relid = row[0];

	RSA *id_pub = fetch_public_key( mysql, to_identity );
	RSA *user_priv = load_key( mysql, from_user );

	Encrypt encrypt( id_pub, user_priv );

	/* Include the null in the message. */
	encrypt.signEncrypt( (u_char*)msg, strlen(msg)+1 );
	queue_message_db( mysql, from_user, to_identity, relid, encrypt.sym );
	return 0;
}


bool send_message()
{
	MYSQL *mysql = db_connect();

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

		long send_res = send_message_net( mysql, false, from_user, to_id, relid, 
				msg, strlen(msg), 0 );

		if ( send_res < 0 ) {
			error( "trouble sending message: %ld\n", send_res );

			MYSQL *mysql = db_connect();

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

long run_broadcast_queue_db()
{
	while ( true ) {
		bool itemsLeft = send_broadcast_message();
		if ( !itemsLeft )
			break;
	}
	return 0;
}

long run_message_queue_db()
{
	while ( true ) {
		bool itemsLeft = send_message();
		if ( !itemsLeft )
			break;
	}
	return 0;
}

void run_queue( const char *siteName )
{
	set_config_by_name( siteName );
	if ( c != 0 ) {
		run_broadcast_queue_db();
		run_message_queue_db();
	}
}

