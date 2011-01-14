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

PutKey::PutKey( MYSQL *mysql, long long networkId )
{
	DbQuery query( mysql, 
		"SELECT "
		"	network.dist_name, "
		"	put_broadcast_key.generation, "
		"	put_broadcast_key.broadcast_key "
		"FROM network "
		"JOIN put_broadcast_key "
		"		ON network.id = put_broadcast_key.network_id AND "
		"		network.key_gen = put_broadcast_key.generation "
		"WHERE network.id = %L ",
		networkId );
	
	if ( query.rows() != 1 )
		throw PutKeyFetchError();
	
	MYSQL_ROW row = query.fetchRow();
	distName = row[0];
	generation = parseId( row[1] );
	broadcastKey = row[2];
}

void newBroadcastKey( MYSQL *mysql, long long networkId, long long generation )
{
	/* Generate the relationship and request ids. */
	unsigned char broadcast_key[RELID_SIZE];
	RAND_bytes( broadcast_key, RELID_SIZE );
	const char *bk = binToBase64( broadcast_key, RELID_SIZE );

	DbQuery( mysql, 
		"INSERT INTO put_broadcast_key "
		"( network_id, generation, broadcast_key ) "
		"VALUES ( %L, %L, %e ) ",
		networkId, generation, bk );
}

void Server::publicKey( MYSQL *mysql, const char *user )
{
	DbQuery query( mysql, 
		"SELECT rsa_n, rsa_e "
		"FROM user "
		"JOIN user_keys ON user.user_keys_id = user_keys.id "
		"WHERE user.user = %e", user );
	if ( query.rows() == 0 )
		throw InvalidUser( user );

	/* Everythings okay. */
	MYSQL_ROW row = query.fetchRow();
	bioWrap->printf( "OK %s %s\r\n", row[0], row[1] );
}

long fetchPublicKeyDb( PublicKey &pub, MYSQL *mysql, const char *iduri )
{
	DbQuery keys( mysql, 
		"SELECT rsa_n, rsa_e "
		"FROM identity "
		"JOIN public_key ON identity.id = public_key.identity_id "
		"WHERE identity.iduri = %e",
		iduri );

	/* Check for a result. */
	if ( keys.rows() > 0 ) {
		MYSQL_ROW row = keys.fetchRow();
		pub.n = strdup( row[0] );
		pub.e = strdup( row[1] );
		return 1;
	}

	return 0;
}

long fetchPublicKeyDb( PublicKey &pub, MYSQL *mysql, long long identityId )
{
	DbQuery keys( mysql, 
		"SELECT rsa_n, rsa_e "
		"FROM public_key "
		"WHERE identity_id = %L",
		identityId );

	/* Check for a result. */
	if ( keys.rows() > 0 ) {
		MYSQL_ROW row = keys.fetchRow();
		pub.n = strdup( row[0] );
		pub.e = strdup( row[1] );
		return 1;
	}

	return 0;
}

Keys *loadKey( MYSQL *mysql, const char *user )
{
	Keys *keys = 0;

	DbQuery keyQuery( mysql,
		"SELECT rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp "
		"FROM user "
		"JOIN user_keys ON user.user_keys_id = user_keys.id "
		"WHERE user = %e", user );

	if ( keyQuery.rows() < 1 )
		throw MissingKeys();

	MYSQL_ROW row = keyQuery.fetchRow();

	RSA *rsa = RSA_new();
	rsa->n =    base64ToBn( row[0] );
	rsa->e =    base64ToBn( row[1] );
	rsa->d =    base64ToBn( row[2] );
	rsa->p =    base64ToBn( row[3] );
	rsa->q =    base64ToBn( row[4] );
	rsa->dmp1 = base64ToBn( row[5] );
	rsa->dmq1 = base64ToBn( row[6] );
	rsa->iqmp = base64ToBn( row[7] );

	keys = new Keys;
	keys->rsa = rsa;

	return keys;
}

Keys *loadKey( MYSQL *mysql, User &user )
{
	Keys *keys = 0;

	DbQuery keyQuery( mysql,
		"SELECT rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp "
		"FROM user "
		"JOIN user_keys ON user.user_keys_id = user_keys.id "
		"WHERE user.id = %L", user.id() );

	if ( keyQuery.rows() < 1 )
		throw MissingKeys();

	MYSQL_ROW row = keyQuery.fetchRow();

	RSA *rsa = RSA_new();
	rsa->n =    base64ToBn( row[0] );
	rsa->e =    base64ToBn( row[1] );
	rsa->d =    base64ToBn( row[2] );
	rsa->p =    base64ToBn( row[3] );
	rsa->q =    base64ToBn( row[4] );
	rsa->dmp1 = base64ToBn( row[5] );
	rsa->dmq1 = base64ToBn( row[6] );
	rsa->iqmp = base64ToBn( row[7] );

	keys = new Keys;
	keys->rsa = rsa;

	return keys;
}

