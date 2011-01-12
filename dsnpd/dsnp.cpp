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

void setConfigByUri( const char *uri )
{
	c = config_first;
	while ( c != 0 && strcmp( c->CFG_URI, uri ) != 0 )
		c = c->next;

	if ( c == 0 ) {
		fatal( "bad site\n" );
		exit(1);
	}
}

void setConfigByName( const char *name )
{
	c = config_first;
	while ( c != 0 && strcmp( c->name, name ) != 0 )
		c = c->next;

	if ( c == 0 ) {
		fatal( "bad site\n" );
		exit(1);
	}
}

char *bin2hex( unsigned char *data, long len )
{
	char *res = (char*)malloc( len*2 + 1 );
	for ( int i = 0; i < len; i++ ) {
		unsigned char l = data[i] & 0xf;
		if ( l < 10 )
			res[i*2+1] = '0' + l;
		else
			res[i*2+1] = 'a' + (l-10);

		unsigned char h = data[i] >> 4;
		if ( h < 10 )
			res[i*2] = '0' + h;
		else
			res[i*2] = 'a' + (h-10);
	}
	res[len*2] = 0;
	return res;
}

long hex2bin( unsigned char *dest, long len, const char *src )
{
	long slen = strlen( src ) / 2;
	if ( len < slen )
		return 0;
	
	for ( int i = 0; i < slen; i++ ) {
		char l = src[i*2+1];
		char h = src[i*2];

		if ( '0' <= l && l <= '9' )
			dest[i] = l - '0';
		else
			dest[i] = 10 + (l - 'a');
			
		if ( '0' <= h && h <= '9' )
			dest[i] |= (h - '0') << 4;
		else
			dest[i] |= (10 + (h - 'a')) << 4;
	}
	return slen;
}

AllocString bnToBase64( const BIGNUM *n )
{
	long len = BN_num_bytes(n);
	u_char *bin = new u_char[len];
	BN_bn2bin( n, bin );
	AllocString b64 = binToBase64( bin, len );
	delete[] bin;
	return b64;
}

BIGNUM *base64ToBn( const char *base64 )
{
	u_char *bin = new u_char[strlen(base64)];
	long len = base64ToBin( bin, base64, strlen(base64) );
	BIGNUM *bn = BN_bin2bn( bin, len, 0 );
	delete[] bin;
	return bn;
}

AllocString passHash( const u_char *salt, const char *pass )
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	u_char *pass_comb = new u_char[SALT_SIZE + strlen(pass)];
	memcpy( pass_comb, salt, SALT_SIZE );
	memcpy( pass_comb + SALT_SIZE, pass, strlen(pass) );
	SHA1( pass_comb, SALT_SIZE+strlen(pass), hash );
	return binToBase64( hash, SHA_DIGEST_LENGTH );
}

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

long storePublicKey( MYSQL *mysql, const char *identity, PublicKey &pub )
{
	DbQuery( mysql,
		"INSERT INTO public_key ( identity, rsa_n, rsa_e ) "
		"VALUES ( %e, %e, %e ) ", identity, pub.n, pub.e );
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

long storePublicKey( MYSQL *mysql, long long identityId, PublicKey &pub )
{
	return 0;
}

char *get_site( const char *identity )
{
	char *res = strdup( identity );
	char *last = res + strlen(res) - 1;
	while ( last[-1] != '/' )
		last--;
	*last = 0;
	return res;
}


Keys *loadKey( MYSQL *mysql, const char *user )
{
	Keys *keys = 0;

	DbQuery keyQuery( mysql,
		"SELECT rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp "
		"FROM user "
		"JOIN user_keys ON user.user_keys_id = user_keys.id "
		"WHERE user = %e", user );

	if ( keyQuery.rows() > 0 ) {
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
	}

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
		fatal( "user %s is missing keys", user.user() );

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

AllocString makeIdHash( const char *salt, const char *identity )
{
	/* Make a hash for the identity. */
	String total( "%s%s", salt, identity );
	unsigned char friend_hash[SHA_DIGEST_LENGTH];
	SHA1( (unsigned char*)total.data, total.length+1, friend_hash );
	return binToBase64( friend_hash, SHA_DIGEST_LENGTH );
}

AllocString makeIduriHash( const char *identity )
{
	/* Make a hash for the identity. */
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1( (unsigned char*)identity, strlen(identity), hash );
	return binToBase64( hash, SHA_DIGEST_LENGTH );
}
