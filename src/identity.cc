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

Identity::Identity( MYSQL *mysql, const char *iduri )
:
	mysql(mysql),
	iduri(Pointer(iduri)),
	haveId(false), 
	havePublicKey(false),
	parsed(false),
	_id(-1),
	_publicKey(false)
{}

Identity::Identity( MYSQL *mysql, Identity::ByHash, const char *hash )
:
	mysql(mysql),
	haveId(false), 
	havePublicKey(false),
	parsed(false),
	_id(-1),
	_publicKey(false)
{
	DbQuery find( mysql,
		"SELECT iduri FROM identity WHERE hash = %e", 
		hash );

	if ( find.rows() != 1 )
		throw IdentityHashInvalid();

	MYSQL_ROW row = find.fetchRow();
	iduri = strdup( row[0] );
}

Identity::Identity( MYSQL *mysql, long long _id )
:
	mysql(mysql),
	haveId(true),
	havePublicKey(false),
	parsed(false),
	_id(_id),
	_publicKey(false)
{
	DbQuery find( mysql,
		"SELECT iduri FROM identity WHERE id = %L", 
		_id );

	if ( find.rows() != 1 )
		throw IdentityIdInvalid();

	MYSQL_ROW row = find.fetchRow();
	iduri = strdup( row[0] );
}

Identity::Identity( long long _id, const char *iduri )
:
	mysql(0),
	iduri(Pointer(iduri)),
	haveId(true),
	havePublicKey(false),
	parsed(false),
	_id(_id),
	_publicKey(false)
{
}

Allocated Identity::hash()
{
	return makeIduriHash( iduri );
}

bool Identity::publicKey()
{
	if ( !havePublicKey ) {
		id();

		DbQuery find( mysql,
			"SELECT public_keys FROM identity WHERE id = %L", 
			id() );

		MYSQL_ROW row = find.fetchRow();
		_publicKey = parseBoolean( row[0] );
	}

	return _publicKey;
}


long long Identity::id()
{
	if ( !haveId ) {
		String hash = makeIduriHash( iduri );

		/* Always try to insert. Ignore failures. */
		DbQuery insert( mysql, 
			"INSERT IGNORE INTO identity "
			"( iduri, hash, public_keys ) "
			"VALUES ( %e, %e, false )",
			iduri(), hash()
		);

		if ( insert.affectedRows() > 0 )
			_id = lastInsertId( mysql );
		else {
			DbQuery find( mysql,
				"SELECT id FROM identity WHERE iduri = %e", 
				iduri() );
			MYSQL_ROW row = find.fetchRow();
			_id = strtoll( row[0], 0, 10 );
		}

		haveId = true;
	}

	return _id;
}

void Server::fetchPublicKey( Identity &identity )
{
	if ( ! identity.publicKey() ) {
		String host = Pointer( identity.host() );

		String encPacket = fetchPublicKeyNet( host, identity.iduri );

		/* FIXME: verify contents. */

		/* Store it in the db. */
		DbQuery( mysql,
			"UPDATE identity SET public_keys = true "
			"WHERE id = %L ",
			identity.id() );

		keyAgent.storePublicKey( identity, encPacket );
	}
}

const char *Identity::host()
{
	if ( !parsed )
		parse();
	return _host;
}


