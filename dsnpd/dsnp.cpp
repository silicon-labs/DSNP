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

char *strend( char *s )
{
	return s + strlen(s);
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


CurrentPutKey::CurrentPutKey( MYSQL *mysql, const char *user, const char *group )
{
	DbQuery query( mysql, 
		"SELECT network.id, "
		"	network.key_gen, "
		"	put_broadcast_key.broadcast_key "
		"FROM user "
		"JOIN network "
		"ON user.id = network.user_id "
		"JOIN put_broadcast_key "
		"ON network.id = put_broadcast_key.network_id "
		"WHERE user.user = %e AND "
		"	network.private_name = %e AND "
		"	network.key_gen = put_broadcast_key.generation ", 
		user, group );
	
	if ( query.rows() == 0 ) {
		fatal( "failed to get current put broadcast key for "
			"user %s and group %s\n", user, group );
	}
	if ( query.rows() > 1 ) {
		fatal( "too many results for current put key "
				"user %s and group %s\n", user, group );
	}
	
	MYSQL_ROW row = query.fetchRow();
	networkId = strtoll( row[0], 0, 10 );
	keyGen = strtoll( row[1], 0, 10 );
	broadcastKey.set( row[2] );
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

void publicKey( MYSQL *mysql, const char *user )
{
	DbQuery query( mysql, 
		"SELECT rsa_n, rsa_e "
		"FROM user "
		"JOIN user_keys ON user.user_keys_id = user_keys.id "
		"WHERE user.user = %e", user );
	if ( query.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR user not found\r\n" );
		return;
	}

	/* Everythings okay. */
	MYSQL_ROW row = query.fetchRow();
	BIO_printf( bioOut, "OK %s %s\n", row[0], row[1] );
}

long openInetConnection( const char *hostname, unsigned short port )
{
	sockaddr_in servername;
	hostent *hostinfo;
	long socketFd, connectRes;

	/* Create the socket. */
	socketFd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( socketFd < 0 )
		return ERR_SOCKET_ALLOC;

	/* Lookup the host. */
	servername.sin_family = AF_INET;
	servername.sin_port = htons(port);
	hostinfo = gethostbyname (hostname);
	if ( hostinfo == NULL ) {
		::close( socketFd );
		return ERR_RESOLVING_NAME;
	}

	servername.sin_addr = *(in_addr*)hostinfo->h_addr;

	/* Connect to the listener. */
	connectRes = connect( socketFd, (sockaddr*)&servername, sizeof(servername) );
	if ( connectRes < 0 ) {
		::close( socketFd );
		return ERR_CONNECTING;
	}

	return socketFd;
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

void makeCertsDir()
{
	String dir1( "%s/%s", PKGSTATEDIR, c->name );
	String dir2( "%s/%s/certs", PKGSTATEDIR, c->name );

	/* try each time. */
	mkdir( dir1.data, 0777 );
	mkdir( dir2.data, 0777 );
}

Keys *fetchPublicKey( MYSQL *mysql, const char *iduri )
{
	IdentityOrig identity(iduri);
	identity.parse();

	/* First try to fetch the public key from the database. */
	PublicKey pub;
	long result = fetchPublicKeyDb( pub, mysql, iduri );
	if ( result < 0 )
		return 0;

	/* If the db fetch failed, get the public key off the net. */
	if ( result == 0 ) {
		char *site = get_site( iduri );
		fetchPublicKeyNet( pub, site, identity.host, identity.user );

		/* Store it in the db. */
		storePublicKey( mysql, identity.identity, pub );
	}

	RSA *rsa = RSA_new();
	rsa->n = base64ToBn( pub.n );
	rsa->e = base64ToBn( pub.e );

	Keys *keys = new Keys;
	keys->rsa = rsa;

	return keys;
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
		fatal( "user %s is missing keys", user.user );

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

long sendMessageNow( MYSQL *mysql, bool prefriend, const char *from_user,
		const char *to_identity, const char *put_relid,
		const char *msg, char **result_msg )
{
	Keys *id_pub, *user_priv;
	Encrypt encrypt;
	int encrypt_res;

	id_pub = fetchPublicKey( mysql, to_identity );
	user_priv = loadKey( mysql, from_user );

	encrypt.load( id_pub, user_priv );

	/* Include the null in the message. */
	encrypt_res = encrypt.signEncrypt( (u_char*)msg, strlen(msg) );

	message( "send_message_now sending to: %s\n", to_identity );
	return sendMessageNet( mysql, prefriend, from_user, to_identity, put_relid, encrypt.sym,
			strlen(encrypt.sym), result_msg );
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

void login( MYSQL *mysql, const char *user, const char *pass )
{
	const long lasts = LOGIN_TOKEN_LASTS;

	DbQuery login( mysql, 
		"SELECT user, pass_salt, pass FROM user WHERE user = %e", user );

	if ( login.rows() == 0 )
		throw InvalidLogin( user, pass, "bad user" );

	MYSQL_ROW row = login.fetchRow();
	char *salt_str = row[1];
	char *pass_str = row[2];

	/* Hash the password using the sale found in the DB. */
	u_char pass_salt[SALT_SIZE];
	base64ToBin( pass_salt, salt_str, strlen(salt_str) );
	String pass_hashed = passHash( pass_salt, pass );

	/* Check the login. */
	if ( strcmp( pass_hashed, pass_str ) != 0 )
		throw InvalidLogin( user, pass, "bad pass" );

	/* Login successful. Make a token. */
	u_char token[TOKEN_SIZE];
	RAND_bytes( token, TOKEN_SIZE );
	String tokenStr = binToBase64( token, TOKEN_SIZE );

	/* Record the token. */
	DbQuery loginToken( mysql, 
		"INSERT INTO login_token ( user, login_token, expires ) "
		"VALUES ( %e, %e, date_add( now(), interval %l second ) )", 
		user, tokenStr.data, lasts );

	String identity( "%s%s/", c->CFG_URI, user );
	String idHashStr = makeIduriHash( identity );

	BIO_printf( bioOut, "OK %s %s %ld\r\n", idHashStr.data, tokenStr.data, lasts );

	message("login of %s successful\n", user );
}

char *decrypt_result( MYSQL *mysql, const char *from_user, 
		const char *to_identity, const char *user_message )
{
	Keys *id_pub, *user_priv;
	Encrypt encrypt;
	int decrypt_res;

	::message( "decrypting result %s %s %s\n", from_user, to_identity, user_message );

	user_priv = loadKey( mysql, from_user );
	id_pub = fetchPublicKey( mysql, to_identity );

	encrypt.load( id_pub, user_priv );
	message( "about to\n");
	decrypt_res = encrypt.decryptVerify( user_message );

	if ( decrypt_res < 0 ) {
		message( "decrypt_verify failed\n");
		return 0;
	}

	message( "decrypt_result: %s\n", encrypt.decrypted );

	return strdup((char*)encrypt.decrypted);
}

long long User::id()
{
	if ( !haveId ) {
		DbQuery find( mysql,
			"SELECT id FROM user WHERE user = %e", 
			user );

		if ( find.rows() > 0 ) {
			_id = strtoll( find.fetchRow()[0], 0, 10 );
			haveId = true;
		}
	}
	return _id;
}

AllocString Identity::hash()
{
	return makeIduriHash( iduri );
}

long long Identity::id()
{
	if ( !haveId ) {
		String hash = makeIduriHash( iduri );

		/* Always, try to insert. Ignore failures. FIXME: need to loop on the
		 * random selection here. */
		DbQuery insert( mysql, 
			"INSERT IGNORE INTO identity "
			"( iduri, hash ) "
			"VALUES ( %e, %e )",
			iduri, hash.data
		);

		if ( insert.affectedRows() > 0 )
			_id = lastInsertId( mysql );
		else {
			DbQuery find( mysql,
				"SELECT id FROM identity WHERE iduri = %e", 
				iduri );
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
