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
			message( "ERROR trouble sending message: %ld\n", send_res );

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
		long send_res = send_message_net( mysql, false, from_user, to_id, relid, 
				msg, strlen(msg), 0 );

		if ( send_res < 0 ) {
			message( "ERROR trouble sending message: %ld\n", send_res );

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

