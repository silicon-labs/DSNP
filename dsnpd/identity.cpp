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
#include "error.h"

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

long fetchPublicKeyDb( PublicKey &pub, MYSQL *mysql, long long identityId );
long fetchPublicKeyDb( PublicKey &pub, MYSQL *mysql, const char *iduri );

Identity::Identity( MYSQL *mysql, const char *iduri )
:
	mysql(mysql),
	iduri(iduri),
	haveId(false), 
	parsed(false),
	_id(-1)
{}

Identity::Identity( MYSQL *mysql, long long _id )
:
	mysql(mysql),
	haveId(true),
	parsed(false),
	_id(_id)
{
	DbQuery find( mysql,
		"SELECT iduri FROM identity WHERE id = %L", 
		_id );

	if ( find.rows() != 1 )
		throw IdentityIdInvalid();

	MYSQL_ROW row = find.fetchRow();
	iduri = strdup( row[0] );
}

AllocString Identity::hash()
{
	return makeIduriHash( iduri );
}

long long Identity::id()
{
	if ( !haveId ) {
		String hash = makeIduriHash( iduri );

		/* Always try to insert. Ignore failures. */
		DbQuery insert( mysql, 
			"INSERT IGNORE INTO identity "
			"( iduri, hash ) "
			"VALUES ( %e, %e )",
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

Keys *Identity::fetchPublicKey()
{
	/* Make sure the identity is in the database. */
	id();
	parse();

	/* First try to fetch the public key from the database. */
	PublicKey pub;
	long result = fetchPublicKeyDb( pub, mysql, _id );

	/* If the db fetch failed, get the public key off the net. */
	if ( result == 0 ) {
		fetchPublicKeyNet( pub, _site, _host, _user );

		/* Store it in the db. */
		DbQuery( mysql,
			"INSERT INTO public_key ( identity_id, rsa_n, rsa_e ) "
			"VALUES ( %L, %e, %e ) ", _id, pub.n, pub.e );
	}

	RSA *rsa = RSA_new();
	rsa->n = base64ToBn( pub.n );
	rsa->e = base64ToBn( pub.e );

	Keys *keys = new Keys;
	keys->rsa = rsa;

	return keys;

}

const char *Identity::host()
{
	if ( !parsed )
		parse();
	return _host;
}

const char *Identity::user()
{
	if ( !parsed )
		parse();
	return _user;
}

const char *Identity::site()
{
	if ( !parsed )
		parse();
	return _site;
}


