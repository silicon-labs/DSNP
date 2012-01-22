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

#include "dsnp.h"
#include "encrypt.h"
#include "string.h"
#include "error.h"
#include "keyagent.h"

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
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include <openssl/pem.h>
#include <openssl/err.h>

PutKey::PutKey( MYSQL *mysql, long long networkId )
{
	DbQuery query( mysql, 
		"SELECT "
		"	network.dist_name, "
		"	put_broadcast_key.generation, "
		"	put_broadcast_key.id "
		"FROM network "
		"JOIN put_broadcast_key ON "
		"	network.id = put_broadcast_key.network_id AND "
		"	network.key_gen = put_broadcast_key.generation "
		"WHERE network.id = %L ",
		networkId );
	
	if ( query.rows() != 1 )
		throw PutKeyFetchError();
	
	MYSQL_ROW row = query.fetchRow();
	distName = row[0];
	generation = parseId( row[1] );
	id = parseId( row[2] );
}

void Server::newBroadcastKey( long long networkId, long long generation )
{
	/* Generate the relationship and request ids. */
	unsigned char broadcastKeyBin[RELID_SIZE];
	RAND_bytes( broadcastKeyBin, RELID_SIZE );
	String broadcastKey = binToBase64( broadcastKeyBin, RELID_SIZE );

	DbQuery( mysql, 
		"INSERT INTO put_broadcast_key "
		"( network_id, generation ) "
		"VALUES ( %L, %L ) ",
		networkId, generation );

	DbQuery findId( mysql, 
		"SELECT id FROM put_broadcast_key "
		"WHERE network_id = %L AND generation = %L ",
		networkId, generation );

	MYSQL_ROW row = findId.fetchRow();
	long long id = parseId( row[0] );

	keyAgent.storePutBroadcastKey( id, broadcastKey );
}

void Server::publicKey( const String &_user )
{
	User user( mysql, _user );
	keyAgent.publicKey( user );

	bioWrap.returnOkServer( keyAgent.pubSet );
}
