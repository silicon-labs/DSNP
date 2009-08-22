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

#include "sppd.h"
#include "encrypt.h"
#include "string.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOGIN_TOKEN_LASTS 86400

void set_config_by_uri( const char *uri )
{
	c = config_first;
	while ( c != 0 && strcmp( c->CFG_URI, uri ) != 0 )
		c = c->next;

	if ( c == 0 ) {
		fatal( "bad site\n" );
		exit(1);
	}
}

void set_config_by_name( const char *name )
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

AllocString bn_to_base64( const BIGNUM *n )
{
	long len = BN_num_bytes(n);
	u_char *bin = new u_char[len];
	BN_bn2bin( n, bin );
	AllocString b64 = bin_to_base64( bin, len );
	delete[] bin;
	return b64;
}

BIGNUM *base64_to_bn( const char *base64 )
{
	u_char *bin = new u_char[strlen(base64)];
	long len = base64_to_bin( bin, 0, base64 );
	BIGNUM *bn = BN_bin2bn( bin, len, 0 );
	delete[] bin;
	return bn;
}

char *pass_hash( const u_char *pass_salt, const char *pass )
{
	unsigned char pass_hash[SHA_DIGEST_LENGTH];
	u_char *pass_comb = new u_char[SALT_SIZE + strlen(pass)];
	memcpy( pass_comb, pass_salt, SALT_SIZE );
	memcpy( pass_comb + SALT_SIZE, pass, strlen(pass) );
	SHA1( pass_comb, SALT_SIZE+strlen(pass), pass_hash );
	return bin_to_base64( pass_hash, SHA_DIGEST_LENGTH );
}

int current_put_bk( MYSQL *mysql, const char *user, long long &generation, String &bk )
{
	int retVal = 0;

	DbQuery query( mysql, 
		"SELECT user.put_generation, broadcast_key "
		"FROM put_broadcast_key JOIN user "
		"WHERE user.user = put_broadcast_key.user AND "
		"	put_broadcast_key.generation <= user.put_generation AND"
		"	user.user = %e "
		"ORDER BY put_generation DESC", user );
	
	if ( query.rows() > 0 ) {
		MYSQL_ROW row = query.fetchRow();

		generation = strtoll( row[0], 0, 10 );
		bk.set( row[1] );
		retVal = 1;
	}

	return retVal;
}

void new_broadcast_key( MYSQL *mysql, const char *user, long long generation )
{
	unsigned char broadcast_key[RELID_SIZE];
	const char *bk = 0;

	/* Generate the relationship and request ids. */
	RAND_bytes( broadcast_key, RELID_SIZE );
	bk = bin_to_base64( broadcast_key, RELID_SIZE );

	exec_query( mysql, 
		"INSERT INTO put_broadcast_key "
		"( user, generation, broadcast_key ) "
		"VALUES ( %e, %L, %e ) ",
		user, generation, bk );
}

void try_new_user( MYSQL *mysql, const char *user, const char *pass, const char *email )
{
	//char *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	char *pass_hashed, *pass_salt_str, *id_salt_str;
	u_char pass_salt[SALT_SIZE], id_salt[SALT_SIZE];

	RAND_bytes( pass_salt, SALT_SIZE );
	pass_salt_str = bin_to_base64( pass_salt, SALT_SIZE );
	message("pass_salt_str: %s\n", bin2hex( pass_salt, SALT_SIZE ) );
	message("pass: %s\n", pass );

	RAND_bytes( id_salt, SALT_SIZE );
	id_salt_str = bin_to_base64( id_salt, SALT_SIZE );

	/* Generate a new key. */
	RSA *rsa = RSA_generate_key( 1024, RSA_F4, 0, 0 );
	if ( rsa == 0 ) {
		BIO_printf( bioOut, "ERROR key generation failed\r\n");
		return;
	}

	/* Extract the components to hex strings. */
	String n = bn_to_base64( rsa->n );
	String e = bn_to_base64( rsa->e );
	String d = bn_to_base64( rsa->d );
	String p = bn_to_base64( rsa->p );
	String q = bn_to_base64( rsa->q );
	String dmp1 = bn_to_base64( rsa->dmp1 );
	String dmq1 = bn_to_base64( rsa->dmq1 );
	String iqmp = bn_to_base64( rsa->iqmp );

	/* Hash the password. */
	pass_hashed = pass_hash( pass_salt, pass );

	/* Execute the insert. */
	exec_query( mysql,
		"INSERT INTO user "
		"("
		"	user, pass_salt, pass, email, id_salt, put_generation, "
		"	rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp "
		")"
		"VALUES ( %e, %e, %e, %e, %e, 1, %e, %e, %e, %e, %e, %e, %e, %e );", 
		user, pass_salt_str, pass_hashed, email, id_salt_str,
		n.data, e.data, d.data, p.data, q.data, dmp1.data, dmq1.data, iqmp.data );

	RSA_free( rsa );
	
	String photoDirCmd( "umask 0002; mkdir %s/%s", c->CFG_PHOTO_DIR, user );
	message("system: %s\n", photoDirCmd.data );
	system( photoDirCmd );
}

void new_user( MYSQL *mysql, const char *user, const char *pass, const char *email )
{
	exec_query( mysql, "LOCK TABLES user WRITE;");

	/* Query the user. */
	DbQuery userCheck( mysql, "SELECT user FROM user WHERE user = %e", user );
	if ( userCheck.fetchRow() ) {
		BIO_printf( bioOut, "ERROR user exists\r\n" );
		exec_query( mysql, "UNLOCK TABLES;" );
		return;
	}

	try_new_user( mysql, user, pass, email );
	BIO_printf( bioOut, "OK\r\n" );

	exec_query( mysql, "UNLOCK TABLES;" );

	/* Make the first broadcast key for the user. */
	new_broadcast_key( mysql, user, 1 );
}

void public_key( MYSQL *mysql, const char *user )
{
	MYSQL_RES *result;
	MYSQL_ROW row;

	/* Query the user. */
	exec_query( mysql, "SELECT rsa_n, rsa_e FROM user WHERE user = %e", user );

	/* Check for a result. */
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		BIO_printf( bioOut, "ERROR user not found\r\n" );
		goto free_result;
	}

	/* Everythings okay. */
	BIO_printf( bioOut, "OK %s %s\n", row[0], row[1] );

free_result:
	mysql_free_result( result );
}

long open_inet_connection( const char *hostname, unsigned short port )
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

long fetch_public_key_db( PublicKey &pub, MYSQL *mysql, const char *identity )
{
	long result = 0;
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql, 
		"SELECT rsa_n, rsa_e FROM public_key WHERE identity = %e", identity );
	if ( query_res != 0 ) {
		result = ERR_QUERY_ERROR;
		goto query_fail;
	}

	/* Check for a result. */
	select_res= mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row ) {
		pub.n = strdup( row[0] );
		pub.e = strdup( row[1] );
		result = 1;
	}

	/* Done. */
	mysql_free_result( select_res );

query_fail:
	return result;
}

long store_public_key( MYSQL *mysql, const char *identity, PublicKey &pub )
{
	long result = 0, query_res;

	query_res = exec_query( mysql,
		"INSERT INTO public_key ( identity, rsa_n, rsa_e ) "
		"VALUES ( %e, %e, %e ) ", identity, pub.n, pub.e );

	if ( query_res != 0 ) {
		result = ERR_QUERY_ERROR;
		goto query_fail;
	}

query_fail:
	return result;
}

RSA *fetch_public_key( MYSQL *mysql, const char *identity )
{
	PublicKey pub;
	RSA *rsa;

	Identity id( identity );
	id.parse();

	/* First try to fetch the public key from the database. */
	long result = fetch_public_key_db( pub, mysql, identity );
	if ( result < 0 )
		return 0;

	/* If the db fetch failed, get the public key off the net. */
	if ( result == 0 ) {
		char *site = get_site( identity );
		result = fetch_public_key_net( pub, site, id.host, id.user );
		if ( result < 0 )
			return 0;

		/* Store it in the db. */
		result = store_public_key( mysql, identity, pub );
		if ( result < 0 )
			return 0;
	}

	rsa = RSA_new();
	rsa->n = base64_to_bn( pub.n );
	rsa->e = base64_to_bn( pub.e );

	return rsa;
}


RSA *load_key( MYSQL *mysql, const char *user )
{
	long query_res;
	MYSQL_RES *result;
	MYSQL_ROW row;
	RSA *rsa;

	query_res = exec_query( mysql,
		"SELECT rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp "
		"FROM user WHERE user = %e", user );

	if ( query_res != 0 )
		goto query_fail;

	/* Check for a result. */
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		goto free_result;
	}

	/* Everythings okay. */
	rsa = RSA_new();
	rsa->n =    base64_to_bn( row[0] );
	rsa->e =    base64_to_bn( row[1] );
	rsa->d =    base64_to_bn( row[2] );
	rsa->p =    base64_to_bn( row[3] );
	rsa->q =    base64_to_bn( row[4] );
	rsa->dmp1 = base64_to_bn( row[5] );
	rsa->dmq1 = base64_to_bn( row[6] );
	rsa->iqmp = base64_to_bn( row[7] );

free_result:
	mysql_free_result( result );
query_fail:
	return rsa;
}

bool friend_claim_exists( MYSQL *mysql, const char *user, const char *identity )
{
	MYSQL_RES *select_res;

	/* Check to see if there is already a friend claim. */
	exec_query( mysql, "SELECT user, friend_id FROM friend_claim "
		"WHERE user = %e AND friend_id = %e",
		user, identity );
	select_res = mysql_store_result( mysql );
	if ( mysql_num_rows( select_res ) != 0 )
		return true;

	return false;
}

bool friend_request_exists( MYSQL *mysql, const char *user, const char *identity )
{
	MYSQL_RES *select_res;

	exec_query( mysql, "SELECT for_user, from_id FROM friend_request "
		"WHERE for_user = %e AND from_id = %e",
		user, identity );
	select_res = mysql_store_result( mysql );
	if ( mysql_num_rows( select_res ) != 0 )
		return true;

	return false;
}

void relid_request( MYSQL *mysql, const char *user, const char *identity )
{
	/* a) verifies challenge response
	 * b) fetches $URI/id.asc (using SSL)
	 * c) randomly generates a one-way relationship id ($FR-RELID)
	 * d) randomly generates a one-way request id ($FR-REQID)
	 * e) encrypts $FR-RELID to friender and signs it
	 * f) makes message available at $FR-URI/friend-request/$FR-REQID.asc
	 * g) redirects the user's browser to $URI/return-relid?uri=$FR-URI&reqid=$FR-REQID
	 */

	int sigRes;
	RSA *user_priv, *id_pub;
	unsigned char requested_relid[RELID_SIZE], fr_reqid[REQID_SIZE];
	char *requested_relid_str, *reqid_str;
	Encrypt encrypt;

	/* Check for the existence of a friend claim. */
	if ( friend_claim_exists( mysql, user, identity ) ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_FRIEND_CLAIM_EXISTS );
		return;
	}

	/* Check for the existence of a friend request. */
	if ( friend_request_exists( mysql, user, identity ) ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_FRIEND_REQUEST_EXISTS );
		return;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity );
	if ( id_pub == 0 ) {
		BIO_printf( bioOut, "ERROR %d\n", ERROR_PUBLIC_KEY );
		return;
	}

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	/* Generate the relationship and request ids. */
	RAND_bytes( requested_relid, RELID_SIZE );
	RAND_bytes( fr_reqid, REQID_SIZE );

	/* Encrypt and sign the relationship id. */
	encrypt.load( id_pub, user_priv );
	sigRes = encrypt.signEncrypt( requested_relid, RELID_SIZE );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}
	
	/* Store the request. */
	requested_relid_str = bin_to_base64( requested_relid, RELID_SIZE );
	reqid_str = bin_to_base64( fr_reqid, REQID_SIZE );

	exec_query( mysql,
		"INSERT INTO relid_request "
		"( for_user, from_id, requested_relid, reqid, msg_sym ) "
		"VALUES( %e, %e, %e, %e, %e )",
		user, identity, requested_relid_str, reqid_str, encrypt.sym );
	
	/* Return the request id for the requester to use. */
	BIO_printf( bioOut, "OK %s\r\n", reqid_str );

	free( requested_relid_str );
	free( reqid_str );
}

void fetch_requested_relid( MYSQL *mysql, const char *reqid )
{
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql,
		"SELECT msg_sym FROM relid_request WHERE reqid = %e", reqid );

	if ( query_res != 0 ) {
		BIO_printf( bioOut, "ERR\r\n" );
		return;
	}

	/* Check for a result. */
	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row )
		BIO_printf( bioOut, "OK %s\r\n", row[0] );
	else
		BIO_printf( bioOut, "ERROR\r\n" );

	/* Done. */
	mysql_free_result( select_res );
}

long store_relid_response( MYSQL *mysql, const char *identity, const char *fr_relid_str,
		const char *fr_reqid_str, const char *relid_str, const char *reqid_str, 
		const char *sym )
{
	int result = exec_query( mysql,
		"INSERT INTO relid_response "
		"( from_id, requested_relid, returned_relid, reqid, msg_sym ) "
		"VALUES ( %e, %e, %e, %e, %e )",
		identity, fr_relid_str, relid_str, 
		reqid_str, sym );
	
	return result;
}

char *make_id_hash( const char *salt, const char *identity )
{
	/* Make a hash for the identity. */
	long len = strlen(salt) + strlen(identity) + 1;
	char *total = new char[len];
	sprintf( total, "%s%s", salt, identity );
	unsigned char friend_hash[SHA_DIGEST_LENGTH];
	SHA1( (unsigned char*)total, len, friend_hash );
	return bin_to_base64( friend_hash, SHA_DIGEST_LENGTH );
}

long store_friend_claim( MYSQL *mysql, const char *user, 
		const char *identity, const char *id_salt, const char *put_relid, const char *get_relid )
{
	char *friend_hash_str = make_id_hash( id_salt, identity );

	/* Insert the friend claim. */
	exec_query( mysql, "INSERT INTO friend_claim "
		"( user, friend_id, friend_salt, friend_hash, put_relid, get_relid ) "
		"VALUES ( %e, %e, %e, %e, %e, %e );",
		user, identity, id_salt, friend_hash_str, put_relid, get_relid );

	return 0;
}

void relid_response( MYSQL *mysql, const char *user, 
		const char *fr_reqid_str, const char *identity )
{
	/*  a) verifies browser is logged in as owner
	 *  b) fetches $FR-URI/id.asc (using SSL)
	 *  c) fetches $FR-URI/friend-request/$FR-REQID.asc 
	 *  d) decrypts and verifies $FR-RELID
	 *  e) randomly generates $RELID
	 *  f) randomly generates $REQID
	 *  g) encrypts "$FR-RELID $RELID" to friendee and signs it
	 *  h) makes message available at $URI/request-return/$REQID.asc
	 *  i) redirects the friender to $FR-URI/friend-final?uri=$URI&reqid=$REQID
	 */

	int verifyRes, fetchRes, sigRes;
	RSA *user_priv, *id_pub;
	unsigned char *requested_relid;
	unsigned char response_relid[RELID_SIZE], response_reqid[REQID_SIZE];
	char *requested_relid_str, *response_relid_str, *response_reqid_str;
	unsigned char message[RELID_SIZE*2];
	Encrypt encrypt;

	Identity id( identity );
	id.parse();

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, id.identity );
	if ( id_pub == 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_PUBLIC_KEY );
		return;
	}

	RelidEncSig encsig;
	fetchRes = fetch_requested_relid_net( encsig, id.site, id.host, fr_reqid_str );
	if ( fetchRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_FETCH_REQUESTED_RELID );
		return;
	}

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	/* Decrypt and verify the requested_relid. */
	encrypt.load( id_pub, user_priv );

	verifyRes = encrypt.decryptVerify( encsig.sym );
	if ( verifyRes < 0 ) {
		::message("relid_response: ERROR_DECRYPT_VERIFY\n" );
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPT_VERIFY );
		return;
	}

	/* Verify the message is the right size. */
	if ( encrypt.decLen != RELID_SIZE ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPTED_SIZE );
		return;
	}

	/* This should not be deleted as long as we don't do any more decryption. */
	requested_relid = encrypt.decrypted;
	
	/* Generate the relationship and request ids. */
	RAND_bytes( response_relid, RELID_SIZE );
	RAND_bytes( response_reqid, REQID_SIZE );

	memcpy( message, requested_relid, RELID_SIZE );
	memcpy( message+RELID_SIZE, response_relid, RELID_SIZE );

	/* Encrypt and sign using the same credentials. */
	sigRes = encrypt.signEncrypt( message, RELID_SIZE*2 );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}

	/* Store the request. */
	requested_relid_str = bin_to_base64( requested_relid, RELID_SIZE );
	response_relid_str = bin_to_base64( response_relid, RELID_SIZE );
	response_reqid_str = bin_to_base64( response_reqid, REQID_SIZE );

	store_relid_response( mysql, identity, requested_relid_str, fr_reqid_str, 
			response_relid_str, response_reqid_str, encrypt.sym );

	/* Insert the friend claim. */
	exec_query( mysql, "INSERT INTO sent_friend_request "
		"( from_user, for_id, requested_relid, returned_relid ) "
		"VALUES ( %e, %e, %e, %e );",
		user, identity, requested_relid_str, response_relid_str );
	
	/* Return the request id for the requester to use. */
	BIO_printf( bioOut, "OK %s\r\n", response_reqid_str );

	free( requested_relid_str );
	free( response_relid_str );
	free( response_reqid_str );
}

void fetch_response_relid( MYSQL *mysql, const char *reqid )
{
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	/* Execute the query. */
	query_res = exec_query( mysql,
		"SELECT msg_sym FROM relid_response WHERE reqid = %e;", reqid );
	
	if ( query_res != 0 ) {
		BIO_printf( bioOut, "ERR\r\n" );
		return;
	}

	/* Check for a result. */
	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row )
		BIO_printf( bioOut, "OK %s\r\n", row[0] );
	else
		BIO_printf( bioOut, "ERR\r\n" );

	/* Done. */
	mysql_free_result( select_res );
}

long verify_returned_fr_relid( MYSQL *mysql, unsigned char *fr_relid )
{
	long result = 0;
	char *requested_relid_str = bin_to_base64( fr_relid, RELID_SIZE );
	int query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql,
		"SELECT from_id FROM relid_request WHERE requested_relid = %e", 
		requested_relid_str );

	/* Execute the query. */
	if ( query_res != 0 ) {
		result = -1;
		goto query_fail;
	}

	/* Check for a result. */
	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row )
		result = 1;

	mysql_free_result( select_res );

query_fail:
	return result;
}

void friend_final( MYSQL *mysql, const char *user, const char *reqid_str, const char *identity )
{
	/* a) fetches $URI/request-return/$REQID.asc 
	 * b) decrypts and verifies message, must contain correct $FR-RELID
	 * c) stores request for friendee to accept/deny
	 */

	int verifyRes, fetchRes;
	RSA *user_priv, *id_pub;
	unsigned char *message;
	unsigned char requested_relid[RELID_SIZE], returned_relid[RELID_SIZE];
	char *requested_relid_str, *returned_relid_str;
	unsigned char user_reqid[REQID_SIZE];
	char *user_reqid_str;
	Encrypt encrypt;
	Identity id( identity );
	id.parse();

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity );
	if ( id_pub == 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_PUBLIC_KEY );
		return;
	}

	RelidEncSig encsig;
	fetchRes = fetch_response_relid_net( encsig, id.site, id.host, reqid_str );
	if ( fetchRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_FETCH_RESPONSE_RELID );
		return;
	}
	
	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	encrypt.load( id_pub, user_priv );

	verifyRes = encrypt.decryptVerify( encsig.sym );
	if ( verifyRes < 0 ) {
		::message("friend_final: ERROR_DECRYPT_VERIFY\n" );
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPT_VERIFY );
		return;
	}

	/* Verify that the message is the right size. */
	if ( encrypt.decLen != RELID_SIZE*2 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPTED_SIZE );
		return;
	}

	message = encrypt.decrypted;

	memcpy( requested_relid, message, RELID_SIZE );
	memcpy( returned_relid, message+RELID_SIZE, RELID_SIZE );

	verifyRes = verify_returned_fr_relid( mysql, requested_relid );
	if ( verifyRes != 1 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_REQUESTED_RELID_MATCH );
		return;
	}
		
	requested_relid_str = bin_to_base64( requested_relid, RELID_SIZE );
	returned_relid_str = bin_to_base64( returned_relid, RELID_SIZE );

	/* Make a user request id. */
	RAND_bytes( user_reqid, REQID_SIZE );
	user_reqid_str = bin_to_base64( user_reqid, REQID_SIZE );

	exec_query( mysql, 
		"INSERT INTO friend_request "
		" ( for_user, from_id, reqid, requested_relid, returned_relid ) "
		" VALUES ( %e, %e, %e, %e, %e ) ",
		user, identity, user_reqid_str, requested_relid_str, returned_relid_str );
	
	/* Return the request id for the requester to use. */
	BIO_printf( bioOut, "OK\r\n" );

	free( requested_relid_str );
	free( returned_relid_str );
}

long delete_friend_request( MYSQL *mysql, const char *user, const char *user_reqid )
{
	/* Insert the friend claim. */
	exec_query( mysql, 
		"DELETE FROM friend_request WHERE for_user = %e AND reqid = %e;",
		user, user_reqid );

	return 0;
}

long run_broadcast_queue_db( MYSQL *mysql )
{
	int result = 0;
	MYSQL_RES *select_res;
	MYSQL_ROW row;
	long rows;

	/* Table lock. */
	exec_query( mysql, "LOCK TABLES broadcast_queue WRITE");

	/* Extract all messages. */
	exec_query( mysql, 
		"SELECT to_site, relid, generation, message "
		"FROM broadcast_queue" );

	/* Get the result. */
	select_res = mysql_store_result( mysql );

	/* Now clear the table. */
	exec_query( mysql, "DELETE FROM broadcast_queue");

	/* Free the table lock before we process the select results. */
	exec_query( mysql, "UNLOCK TABLES;");

	rows = mysql_num_rows( select_res );
	bool *sent = new bool[rows];
	memset( sent, 0, sizeof(bool)*rows );
	bool unsent = false;

	for ( int i = 0; i < rows; i++ ) {
		row = mysql_fetch_row( select_res );

		char *to_site = row[0];
		char *relid = row[1];
		long long generation = strtoll( row[2], 0, 10 );
		char *msg = row[3];

		long send_res = send_broadcast_net( to_site, relid,
				generation, msg, strlen(msg) );
		if ( send_res < 0 ) {
			::message( "ERROR trouble sending message: %ld\n", send_res );
			sent[i] = false;
			unsent = true;
		}
	}

	if ( unsent ) {
		/* Table lock. */
		exec_query( mysql, "LOCK TABLES broadcast_queue WRITE;");

		mysql_data_seek( select_res, 0 );
		for ( int i = 0; i < rows; i++ ) {
			row = mysql_fetch_row( select_res );

			if ( !sent[i] ) {
				char *to_site = row[0];
				char *relid = row[1];
				char *generation = row[2];
				char *message = row[3];

				::message( "Putting back to the queue: %s %s %s\n", 
						to_site, relid, generation );

				/* Queue the message. */

				exec_query( mysql,
					"INSERT INTO broadcast_queue "
					"( to_site, relid, generation, message ) "
					"VALUES ( %e, %e, %e, %e ) ",
					to_site, relid, generation, message );
			}
		}

		/* Free the table lock before we process the select results. */
		exec_query( mysql, "UNLOCK TABLES;");
	}

	delete[] sent;

	/* Done. */
	mysql_free_result( select_res );

	return result;
}

long run_message_queue_db( MYSQL *mysql )
{
	int result = 0;
	MYSQL_RES *select_res;
	MYSQL_ROW row;
	long rows;

	/* Table lock. */
	exec_query( mysql, "LOCK TABLES message_queue WRITE");

	/* Extract all messages. */
	exec_query( mysql,
		"SELECT from_user, to_id, relid, message FROM message_queue" );

	/* Get the result. */
	select_res = mysql_store_result( mysql );

	/* Now clear the table. */
	exec_query( mysql, "DELETE FROM message_queue");

	/* Free the table lock before we process the select results. */
	exec_query( mysql, "UNLOCK TABLES;");

	rows = mysql_num_rows( select_res );
	bool *sent = new bool[rows];
	memset( sent, 0, sizeof(bool)*rows );
	bool unsent = false;

	for ( int i = 0; i < rows; i++ ) {
		row = mysql_fetch_row( select_res );

		char *from_user = row[0];
		char *to_id = row[1];
		char *relid = row[2];
		char *message = row[3];

		long send_res = send_message_net( mysql, false, from_user, to_id, relid, 
				message, strlen(message), 0 );
		if ( send_res < 0 ) {
			BIO_printf( bioOut, "ERROR trouble sending message: %ld\n", send_res );
			sent[i] = false;
			unsent = true;
		}
	}

	if ( unsent ) {
		/* Table lock. */
		exec_query( mysql, "LOCK TABLES message_queue WRITE;");

		mysql_data_seek( select_res, 0 );
		for ( int i = 0; i < rows; i++ ) {
			row = mysql_fetch_row( select_res );

			char *from_user = row[0];
			char *to_id = row[1];
			char *relid = row[2];
			char *message = row[3];

			if ( !sent[i] ) {
				BIO_printf( bioOut, "Putting back to the queue: %s %s %s %s\n", 
						row[0], row[1], row[2], row[3] );

				exec_query( mysql,
					"INSERT INTO message_queue "
					"( from_user, to_id, relid, message ) "
					"VALUES ( %e, %e, %e, %e ) ",
					from_user, to_id, relid, message );
			}
		}
		/* Free the table lock before we process the select results. */
		exec_query( mysql, "UNLOCK TABLES;");
	}

	delete[] sent;

	/* Done. */
	mysql_free_result( select_res );

	return result;
}


void run_queue( const char *siteName )
{
	MYSQL *mysql, *connect_res;

	set_config_by_name( siteName );

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		BIO_printf( bioOut, "ERROR failed to connect to the database\r\n");
		goto close;
	}

	run_broadcast_queue_db( mysql );
	run_message_queue_db( mysql );

close:
	mysql_close( mysql );
}

int send_current_broadcast_key( MYSQL *mysql, const char *user, const char *identity )
{
	long long generation;
	String broadcast_key;

	/* Get the latest put session key. */
	int bk_result = current_put_bk( mysql, user, generation, broadcast_key );
	if ( bk_result != 1 ) {
		BIO_printf( bioOut, "ERROR fetching session key\r\n");
		return -1;
	}

	int send_res = send_broadcast_key( mysql, user, identity, generation, broadcast_key );
	if ( send_res < 0 )
		error( "sending failed %d\n", send_res );

	return 0;
}

void accept_friend( MYSQL *mysql, const char *user, const char *user_reqid )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	char buf[2048], *result_message = 0;
	char *from_id, *requested_relid, *returned_relid;
	char *id_salt;

	/* Execute the query. */
	exec_query( mysql, "SELECT id_salt FROM user WHERE user = %e", user );

	/* Check for a result. */
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		BIO_printf( bioOut, "ERROR request not found\r\n" );
		return;
	}
	id_salt = row[0];

	/* Execute the query. */
	exec_query( mysql, "SELECT from_id, requested_relid, returned_relid "
		"FROM friend_request "
		"WHERE for_user = %e AND reqid = %e;",
		user, user_reqid );

	/* Check for a result. */
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		BIO_printf( bioOut, "ERROR request not found\r\n" );
		return;
	}

	from_id = row[0];
	requested_relid = row[1];
	returned_relid = row[2];

	/* Notify the requester. */
	sprintf( buf, "notify_accept %s %s %s\r\n", id_salt, requested_relid, returned_relid );
	message( "accept_friend sending: %s to %s from %s\n", buf, from_id, user  );
	int nfa = send_message_now( mysql, true, user, from_id, requested_relid, buf, &result_message );

	if ( nfa < 0 ) {
		BIO_printf( bioOut, "ERROR accept failed with %d\r\n", nfa );
		return;
	}

	notify_accept_result_parser( mysql, user, user_reqid, from_id, 
			requested_relid, returned_relid, result_message );
}

void notify_accept_returned_id_salt( MYSQL *mysql, const char *user, const char *user_reqid, 
		const char *from_id, const char *requested_relid, 
		const char *returned_relid, const char *returned_id_salt )
{
	char buf[2048];
	message( "accept_friend received: %s\n", returned_id_salt );

	/* The friendship has been accepted. Store the claim. The fr_relid is the
	 * one that we made on this end. It becomes the put_relid. */
	store_friend_claim( mysql, user, from_id, returned_id_salt, requested_relid, returned_relid );

	/* Notify the requester. */
	sprintf( buf, "registered %s %s\r\n", requested_relid, returned_relid );
	message( "accept_friend sending: %s to %s from %s\n", buf, from_id, user  );
	send_message_now( mysql, true, user, from_id, requested_relid, buf, 0 );

	/* Remove the user friend request. */
	delete_friend_request( mysql, user, user_reqid );

	forward_tree_insert( mysql, user, from_id, requested_relid );

	BIO_printf( bioOut, "OK\r\n" );
}


long store_ftoken( MYSQL *mysql, const char *user, const char *identity,
		const char *token_str, const char *reqid_str, const char *msg_sym )
{
	long result = 0;
	int query_res;

	query_res = exec_query( mysql,
		"INSERT INTO ftoken_request "
		"( user, from_id, token, reqid, msg_sym ) "
		"VALUES ( %e, %e, %e, %e, %e ) ",
		user, identity, token_str, reqid_str, msg_sym );

	if ( query_res != 0 )
		result = ERR_QUERY_ERROR;

	return result;
}

long check_friend_claim( Identity &identity, MYSQL *mysql, const char *user, 
		const char *friend_hash )
{
	long result = 0;
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql,
		"SELECT friend_id FROM friend_claim WHERE user = %e AND friend_hash = %e",
		user, friend_hash );

	if ( query_res != 0 ) {
		result = ERR_QUERY_ERROR;
		goto query_fail;
	}

	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row ) {
		identity.identity = strdup( row[0] );
		identity.parse();
		result = 1;
	}

	/* Done. */
	mysql_free_result( select_res );

query_fail:
	return result;
}

char *user_identity_hash( MYSQL *mysql, const char *user )
{
	long result = 0;
	long query_res;
	char *identity, *id_hash_str = 0;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql,
		"SELECT id_salt FROM user WHERE user = %e", user );

	if ( query_res != 0 ) {
		result = ERR_QUERY_ERROR;
		goto query_fail;
	}

	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row ) {
		identity = new char[strlen(c->CFG_URI) + strlen(user) + 2];
		sprintf( identity, "%s%s/", c->CFG_URI, user );
		id_hash_str = make_id_hash( row[0], identity );
	}

	/* Done. */
	mysql_free_result( select_res );

query_fail:
	return id_hash_str;
}

void ftoken_request( MYSQL *mysql, const char *user, const char *hash )
{
	int sigRes;
	RSA *user_priv, *id_pub;
	unsigned char flogin_token[TOKEN_SIZE], reqid[REQID_SIZE];
	char *flogin_token_str, *reqid_str;
	long friend_claim;
	Identity friend_id;
	Encrypt encrypt;

	/* Check if this identity is our friend. */
	friend_claim = check_friend_claim( friend_id, mysql, user, hash );
	if ( friend_claim <= 0 ) {
		::message("ftoken_request: hash %s for user %s is not valid\n", hash, user );

		/* No friend claim ... send back a reqid anyways. Don't want to give
		 * away that there is no claim. FIXME: Would be good to fake this with
		 * an appropriate time delay. */
		RAND_bytes( reqid, RELID_SIZE );
		reqid_str = bin_to_base64( reqid, RELID_SIZE );

		/*FIXME: Hang for a bit here instead. */
		BIO_printf( bioOut, "OK %s\r\n", reqid_str );
		return;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, friend_id.identity );
	if ( id_pub == 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_PUBLIC_KEY );
		return;
	}

	/* Load the private key for the user. */
	user_priv = load_key( mysql, user );

	/* Generate the login request id and relationship and request ids. */
	RAND_bytes( flogin_token, TOKEN_SIZE );
	RAND_bytes( reqid, REQID_SIZE );

	encrypt.load( id_pub, user_priv );

	/* Encrypt it. */
	sigRes = encrypt.signEncrypt( flogin_token, TOKEN_SIZE );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}

	/* Store the request. */
	flogin_token_str = bin_to_base64( flogin_token, TOKEN_SIZE );
	reqid_str = bin_to_base64( reqid, REQID_SIZE );

	store_ftoken( mysql, user, friend_id.identity, 
			flogin_token_str, reqid_str, encrypt.sym );

	::message("ftoken_request: %s %s\n", reqid_str, friend_id.identity );

	/* Return the request id for the requester to use. */
	BIO_printf( bioOut, "OK %s %s %s\r\n", reqid_str,
			friend_id.identity, user_identity_hash( mysql, user ) );
}

void fetch_ftoken( MYSQL *mysql, const char *reqid )
{
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql,
		"SELECT msg_sym FROM ftoken_request WHERE reqid = %e", reqid );

	/* Execute the query. */
	if ( query_res != 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DB_ERROR );
		return;
	}

	/* Check for a result. */
	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row )
		BIO_printf( bioOut, "OK %s\r\n", row[0] );
	else
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_NO_FTOKEN );

	/* Done. */
	mysql_free_result( select_res );

	message("fetch_ftoken finished\n");
}

void ftoken_response( MYSQL *mysql, const char *user, const char *hash, 
		const char *flogin_reqid_str )
{
	/*
	 * a) checks that $FR-URI is a friend
	 * b) if browser is not logged in fails the process (no redirect).
	 * c) fetches $FR-URI/tokens/$FR-RELID.asc
	 * d) decrypts and verifies the token
	 * e) redirects the browser to $FP-URI/submit-token?uri=$URI&token=$TOK
	 */
	int verifyRes, fetchRes;
	RSA *user_priv, *id_pub;
	unsigned char *flogin_token;
	char *flogin_token_str;
	long friend_claim;
	Identity friend_id;
	char *site;
	Encrypt encrypt;

	message("ftoken_response\n");

	/* Check if this identity is our friend. */
	friend_claim = check_friend_claim( friend_id, mysql, user, hash );
	if ( friend_claim <= 0 ) {
		/* No friend claim ... we can reveal this since ftoken_response requires
		 * that the user be logged in. */
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_NOT_A_FRIEND );
		return;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, friend_id.identity );
	if ( id_pub == 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_PUBLIC_KEY );
		return;
	}

	site = get_site( friend_id.identity );

	RelidEncSig encsig;
	fetchRes = fetch_ftoken_net( encsig, site, friend_id.host, flogin_reqid_str );
	if ( fetchRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_FETCH_FTOKEN );
		return;
	}

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	encrypt.load( id_pub, user_priv );

	/* Decrypt the flogin_token. */
	verifyRes = encrypt.decryptVerify( encsig.sym );
	if ( verifyRes < 0 ) {
		::message("ftoken_response: ERROR_DECRYPT_VERIFY\n" );
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPT_VERIFY );
		return;
	}

	/* Check the size. */
	if ( encrypt.decLen != REQID_SIZE ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_DECRYPTED_SIZE );
		return;
	}

	flogin_token = encrypt.decrypted;
	flogin_token_str = bin_to_base64( flogin_token, RELID_SIZE );

	exec_query( mysql,
		"INSERT INTO remote_flogin_token "
		"( user, identity, login_token ) "
		"VALUES ( %e, %e, %e )",
		user, friend_id.identity, flogin_token_str );

	/* Return the login token for the requester to use. */
	BIO_printf( bioOut, "OK %s %s\r\n", flogin_token_str, friend_id.identity );

	free( flogin_token_str );
}

void add_get_tree( MYSQL *mysql, const char *user, const char *friend_id, long long generation )
{
	DbQuery check( mysql,
		"SELECT user FROM get_tree "
		"WHERE user = %e AND friend_id = %e AND generation = %L",
		user, friend_id, generation );
	
	if ( check.rows() == 0 ) {
		/* Insert an entry for this relationship. */
		exec_query( mysql, 
			"INSERT INTO get_tree "
			"( user, friend_id, generation )"
			"VALUES ( %e, %e, %L )", user, friend_id, generation );
	}
}

void broadcast_key( MYSQL *mysql, const char *relid, const char *user,
		const char *friend_id, long long generation, const char *bk )
{
	add_get_tree( mysql, user, friend_id, generation );

	/* Make the query. */
	exec_query( mysql, 
			"UPDATE get_tree "
			"SET broadcast_key = %e "
			"WHERE user = %e AND friend_id = %e AND generation = %L",
			bk, user, friend_id, generation );
	
	BIO_printf( bioOut, "OK\n" );
}

void forward_to( MYSQL *mysql, const char *user, const char *friend_id,
		int child_num, long long generation, const char *to_site, const char *relid )
{
	add_get_tree( mysql, user, friend_id, generation );

	switch ( child_num ) {
	case 0:
		exec_query( mysql, 
			"UPDATE get_tree "
			"SET site_ret = %e, relid_ret = %e "
			"WHERE user = %e AND friend_id = %e AND generation = %L",
			to_site, relid, user, friend_id, generation );
		break;
	case 1:
		exec_query( mysql, 
			"UPDATE get_tree "
			"SET site1 = %e, relid1 = %e "
			"WHERE user = %e AND friend_id = %e AND generation = %L",
			to_site, relid, user, friend_id, generation );
		break;
	case 2:
		exec_query( mysql, 
			"UPDATE get_tree "
			"SET site2 = %e, relid2 = %e "
			"WHERE user = %e AND friend_id = %e AND generation = %L",
			to_site, relid, user, friend_id, generation );
		break;
	}

	BIO_printf( bioOut, "OK\n" );
}

long queue_message_db( MYSQL *mysql, const char *from_user,
		const char *to_identity, const char *relid, const char *message )
{
	/* Table lock. */
	exec_query( mysql, "LOCK TABLES message_queue WRITE");

	exec_query( mysql,
		"INSERT INTO message_queue "
		"( from_user, to_id, relid, message ) "
		"VALUES ( %e, %e, %e, %e ) ",
		from_user, to_identity, relid, message );

	/* UNLOCK reset. */
	exec_query( mysql, "UNLOCK TABLES");
	
	return 0;
}

long queue_broadcast_db( MYSQL *mysql, const char *to_site, const char *relid,
		long long generation, const char *msg )
{
	message("queue_broadcast_db\n");

	/* Table lock. */
	exec_query( mysql, "LOCK TABLES broadcast_queue WRITE");

	exec_query( mysql,
		"INSERT INTO broadcast_queue "
		"( to_site, relid, generation, message ) "
		"VALUES ( %e, %e, %L, %e ) ",
		to_site, relid, generation, msg );

	/* UNLOCK reset. */
	exec_query( mysql, "UNLOCK TABLES");

	return 0;
}


long queue_broadcast( MYSQL *mysql, const char *user, const char *msg, long mLen )
{
	long long generation;
	String broadcast_key;

	/* Get the latest put session key. */
	int bk_result = current_put_bk( mysql, user, generation, broadcast_key );
	if ( bk_result != 1 ) {
		BIO_printf( bioOut, "ERROR fetching broadcast key\r\n");
		return -1;
	}

	message("queue_broadcast: using %lld %s\n", generation, broadcast_key.data );

	/* Find root friend. */
	DbQuery rootFriend( mysql,
		"SELECT friend_claim.friend_id, friend_claim.put_relid "
		"FROM friend_claim "
		"JOIN put_tree "
		"ON friend_claim.user = put_tree.user AND "
		"	friend_claim.friend_id = put_tree.friend_id "
		"WHERE friend_claim.user = %e AND put_tree.root = true AND"
		"	put_tree.generation <= %L "
		"ORDER BY generation DESC LIMIT 1",
		user, generation );

	if ( rootFriend.rows() == 0 ) {
		/* Nothing here means that the user has no friends (sniff). */
	}
	else {
		MYSQL_ROW row = rootFriend.fetchRow();
		char *friend_id = row[0];
		char *put_relid = row[1];

		message( "queue_broadcast: using root node: %s\n", friend_id );

		/* Do the encryption. */
		RSA *user_priv = load_key( mysql, user );
		Encrypt encrypt( 0, user_priv );
		encrypt.bkSignEncrypt( broadcast_key, (u_char*)msg, mLen );

		/* Find the root user to send to. */
		Identity id( friend_id );
		id.parse();

		queue_broadcast_db( mysql, id.site, put_relid,
				generation, encrypt.sym );
	}

	return 0;
}

long send_broadcast( MYSQL *mysql, const char *user,
		const char *type, long long resource_id, const char *msg, long mLen )
{
	String timeStr = timeNow();
	String authorId( "%s%s/", c->CFG_URI, user );

	const char *insert = msg;
	long insertLen = mLen;
	String fileData;

	/* If this is a photo we need to read in the file. */
	if ( strcmp( type, "PHT" ) == 0 ) {
		String fileName = stringStartEnd( msg, msg+mLen );
		String path( "%s/%s/%s", c->CFG_PHOTO_DIR, user, fileName.data );
		fileData.allocate( MAX_BRD_PHOTO_SIZE );

		FILE *file = fopen( path, "rb" );
		if ( file == 0 ) {
			::message( "failed to open %s\n", fileName.data );
			return -1;
		}
		long len = fread( fileData.data, 1, MAX_BRD_PHOTO_SIZE, file );
		fclose( file );

		msg = fileData.data;
		mLen = len;
	}

	/* Insert the broadcast message into the published table. */
	exec_query( mysql,
		"INSERT INTO published "
		"( user, author_id, time_published, type, message ) "
		"VALUES ( %e, %e, %e, %e, %d )",
		user, authorId.data, timeStr.data, type, insert, insertLen );

	/* Get the id that was assigned to the message. */
	DbQuery lastInsertId( mysql, "SELECT last_insert_id()" );
	if ( lastInsertId.rows() != 1 )
		return -1;

	long long seq_num = strtoll( lastInsertId.fetchRow()[0], 0, 10 );

	/* Make the full message. */
	String broadcastCmd(
		"direct_broadcast %lld %s %s %lld %ld\r\n%s\r\n", 
		seq_num, timeStr.data, type, resource_id, mLen, msg );

	long sendResult = queue_broadcast( mysql, user, broadcastCmd.data, broadcastCmd.length );
	if ( sendResult < 0 )
		return -1;

	return 0;
}

long submit_broadcast( MYSQL *mysql, const char *user, const char *type,
		long long resource_id, const char *msg, long mLen )
{
	int result = send_broadcast( mysql, user, type, resource_id, msg, mLen );

	if ( result < 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		goto close;
	}

	BIO_printf( bioOut, "OK\r\n" );

close:
	return 0;
}

long send_remote_broadcast( MYSQL *mysql, const char *user, const char *author_id,
		const char *author_hash, long long generation,
		long long seq_num, const char *msg, long mLen, const char *encMessage )
{
	long encMessageLen = strlen(encMessage);

	/* Make the full message. */
	String command( 
		"remote_broadcast %s %lld %lld %ld\r\n", 
		author_hash, generation, seq_num, encMessageLen );
	String full = addMessageData( command, encMessage, encMessageLen );

	long sendResult = queue_broadcast( mysql, user, full.data, full.length );
	if ( sendResult < 0 )
		return -1;

	return 0;
}

long submit_remote_broadcast( MYSQL *mysql, const char *to_user, 
		const char *author_id, const char *author_hash, 
		const char *token, const char *type, const char *msg, long mLen )
{
	int res;
	RSA *user_priv, *id_pub;
	Encrypt encrypt;
	time_t curTime;
	struct tm curTM, *tmRes;
	MYSQL_RES *result;
	MYSQL_ROW row;
	char time_str[64];
	long long seq_num;
	char *result_message;

	/* Get the current time. */
	curTime = time(NULL);

	/* Convert to struct tm. */
	tmRes = localtime_r( &curTime, &curTM );
	if ( tmRes == 0 )
		return -1;

	/* Format for the message. */
	if ( strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &curTM )  == 0 ) 
		return -1;

	/* Find the relid from subject to author. */
	DbQuery putRelidQuery( mysql,
			"SELECT put_relid FROM friend_claim WHERE user = %e AND friend_id = %e",
			to_user, author_id );
	if ( putRelidQuery.rows() != 1 ) {
		message("find of put_relid from subject to author failed\n");
		return -1;
	}

	String putRelid = putRelidQuery.fetchRow()[0];

	String subjectId( "%s%s/", c->CFG_URI, to_user );

	/* Insert the broadcast message into the published table. */
	exec_query( mysql,
		"INSERT INTO published "
		"( user, author_id, subject_id, time_published, type, message ) "
		"VALUES ( %e, %e, %e, %e, %e, %d )",
		to_user, author_id, subjectId.data, time_str, type, msg, mLen );

	/* Get the id that was assigned to the message. */
	exec_query( mysql, "SELECT LAST_INSERT_ID()" );
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row )
		return -1;

	seq_num = strtoll( row[0], 0, 10 );

	user_priv = load_key( mysql, to_user );
	id_pub = fetch_public_key( mysql, author_id );
	encrypt.load( id_pub, user_priv );
	encrypt.signEncrypt( (u_char*)msg, mLen );

	String remotePublishCmd(
		"encrypt_remote_broadcast %s %lld %s %ld\r\n%s\r\n", 
		token, seq_num, type, mLen, msg );

	res = send_message_now( mysql, false, to_user, author_id, putRelid.data,
			remotePublishCmd.data, &result_message );
	if ( res < 0 ) {
		message("encrypt_remote_broadcast message failed\n");
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}

	message("send_message_now returned: %s\n", result_message);

	return encrypted_broadcast_parser( mysql, to_user, author_id, author_hash, seq_num,
			msg, mLen, result_message ) ;
}


long encrypted_broadcast( MYSQL *mysql, const char *to_user, const char *author_id,
		const char *author_hash, long long seq_num, const char *msg, long mLen,
		long long resultGen, const char *resultEnc )
{
	message("result enc: %s\n", resultEnc );
	message("result gen: %lld\n", resultGen );

	long res = send_remote_broadcast( mysql, to_user, author_id, 
			author_hash, resultGen, seq_num, msg, mLen, resultEnc );
	if ( res < 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return -1;
	}
	
	message("remote broadcast okay\n");
	BIO_printf( bioOut, "OK\r\n" );
	return 0;
}


void broadcast( MYSQL *mysql, const char *relid, long long generation, const char *encrypted )
{
	char *user, *friend_id, *broadcast_key;
	char *site1, *relid1;
	char *site2, *relid2;
	RSA *id_pub;
	Encrypt encrypt;
	int decryptRes, parseRes, decLen;
	char *decrypted;

	/* Find the recipient. */
	DbQuery recipient( mysql, 
		"SELECT friend_claim.user, friend_claim.friend_id, "
		"	get_tree.site1, get_tree.relid1, "
		"	get_tree.site2, get_tree.relid2, "
		"	get_tree.broadcast_key "
		"FROM friend_claim JOIN get_tree "
		"ON friend_claim.user = get_tree.user AND "
		"	friend_claim.friend_id = get_tree.friend_id "
		"WHERE friend_claim.get_relid = %e AND get_tree.generation <= %L "
		"ORDER BY get_tree.generation DESC LIMIT 1",
		relid, generation );
	
	if ( recipient.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR bad recipient\r\n");
		return;
	}

	MYSQL_ROW row = recipient.fetchRow();
	user = row[0];
	friend_id = row[1];
	site1 = row[2];
	relid1 = row[3];
	site2 = row[4];
	relid2 = row[5];
	broadcast_key = row[6];

	/* Do the decryption. */
	id_pub = fetch_public_key( mysql, friend_id );
	encrypt.load( id_pub, 0 );
	decryptRes = encrypt.bkDecryptVerify( broadcast_key, encrypted );

	if ( decryptRes < 0 ) {
		message("bkDecryptVerify failed\n");
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}

	/* Take a copy of the decrypted message. */
	decrypted = new char[encrypt.decLen+1];
	memcpy( decrypted, encrypt.decrypted, encrypt.decLen );
	decrypted[encrypt.decLen] = 0;
	decLen = encrypt.decLen;

	message("dispatching broadcast_parser\n");
	parseRes = broadcast_parser( mysql, relid, user, friend_id, decrypted, decLen );
	if ( parseRes < 0 )
		message("broadcast_parser failed\n");

	/* 
	 * Now do the forwarding.
	 */

	if ( site1 != 0 )
		queue_broadcast_db( mysql, site1, relid1, generation, encrypted );

	if ( site2 != 0 )
		queue_broadcast_db( mysql, site2, relid2, generation, encrypted );

	BIO_printf( bioOut, "OK\n" );
}

void direct_broadcast( MYSQL *mysql, const char *relid, const char *user, const char *author_id, 
		long long seq_num, const char *date, const char *type, long long resource_id, const char *msg, long length )
{
	if ( strcmp( type, "PHT" ) == 0 ) {
		char *name = new char[64];
		sprintf( name, "pub-%lld.jpg", seq_num );

		char *path = new char[strlen(c->CFG_PHOTO_DIR) + strlen(user) + 64];
		sprintf( path, "%s/%s/pub-%lld.jpg", c->CFG_PHOTO_DIR, user, seq_num );

		FILE *f = fopen( path, "wb" );
		fwrite( msg, 1, length, f );
		fclose( f );

		msg = name;
		length = strlen( msg );
	}

	exec_query( mysql, 
		"INSERT INTO received "
		"	( for_user, author_id, seq_num, time_published, time_received, type, resource_id, message ) "
		"VALUES ( %e, %e, %L, %e, now(), %e, %L, %d )",
		user, author_id, seq_num, date, type, resource_id, msg, length );
}

void remote_inner( MYSQL *mysql, const char *user, const char *friend_id, const char *author_id,
		long long seq_num, const char *date, const char *type, const char *msg, long mLen )
{
	::message("storing remote innter\n");
	exec_query( mysql, 
		"INSERT INTO received "
		"	( for_user, author_id, subject_id, seq_num, time_published, time_received, type, message ) "
		"VALUES ( %e, %e, %e, %L, %e, now(), %e, %d )",
		user, author_id, friend_id, seq_num, date, type, msg, mLen );
}

void remote_broadcast( MYSQL *mysql, const char *relid, const char *user, const char *friend_id, 
		const char *hash, long long generation, const char *msg, long mLen )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	char *broadcast_key, *author_id;
	RSA *id_pub;
	Encrypt encrypt;
	int decryptRes;

	message( "remote_broadcast\n");
	message( "generation: %lld\n", generation );

	/* Messages has a remote sender and needs to be futher decrypted. */
	exec_query( mysql, 
		"SELECT friend_claim.friend_id, get_tree.broadcast_key "
		"FROM friend_claim "
		"JOIN get_tree "
		"ON friend_claim.user = get_tree.user AND "
		"	friend_claim.friend_id = get_tree.friend_id "
		"WHERE friend_claim.user = %e AND friend_claim.friend_hash = %e AND "
		"	get_tree.generation <= %L "
		"ORDER BY get_tree.generation DESC LIMIT 1",
		user, hash, generation );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row ) {
		author_id = row[0];
		broadcast_key = row[1];

		message( "second level message: %s\n", msg );
		message( "second level author_id: %s\n", author_id );

		/* Do the decryption. */
		id_pub = fetch_public_key( mysql, author_id );
		encrypt.load( id_pub, 0 );
		decryptRes = encrypt.bkDecryptVerify( broadcast_key, msg );

		if ( decryptRes < 0 ) {
			message("second level bkDecryptVerify failed\n");
			BIO_printf( bioOut, "ERROR\r\n" );
			return;
		}

		message( "second level decLen: %d\n", encrypt.decLen );

		remote_broadcast_parser( mysql, user, friend_id, author_id,
				(char*)encrypt.decrypted, encrypt.decLen );
	}
}

long send_message_now( MYSQL *mysql, bool prefriend, const char *from_user,
		const char *to_identity, const char *put_relid,
		const char *msg, char **result_msg )
{
	RSA *id_pub, *user_priv;
	Encrypt encrypt;
	int encrypt_res;

	id_pub = fetch_public_key( mysql, to_identity );
	user_priv = load_key( mysql, from_user );

	encrypt.load( id_pub, user_priv );

	/* Include the null in the message. */
	encrypt_res = encrypt.signEncrypt( (u_char*)msg, strlen(msg)+1 );

	message( "send_message_now sending to: %s\n", to_identity );
	return send_message_net( mysql, prefriend, from_user, to_identity, put_relid, encrypt.sym,
			strlen(encrypt.sym), result_msg );
}

long queue_message( MYSQL *mysql, const char *from_user,
		const char *to_identity, const char *message )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	RSA *id_pub, *user_priv;
	Encrypt encrypt;
	int encrypt_res;
	const char *relid;

	exec_query( mysql, 
		"SELECT put_relid FROM friend_claim "
		"WHERE user = %e AND friend_id = %e ",
		from_user, to_identity );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 )
		goto free_result;
	relid = row[0];

	id_pub = fetch_public_key( mysql, to_identity );
	user_priv = load_key( mysql, from_user );

	encrypt.load( id_pub, user_priv );

	/* Include the null in the message. */
	encrypt_res = encrypt.signEncrypt( (u_char*)message, strlen(message)+1 );

	queue_message_db( mysql, from_user, to_identity, relid, encrypt.sym );
free_result:
	mysql_free_result( result );
	return 0;
}

long send_broadcast_key( MYSQL *mysql, const char *from_user, const char *to_identity, 
		long long generation, const char *broadcast_key )
{
	static char buf[8192];

	sprintf( buf,
		"broadcast_key %lld %s\r\n", 
		generation, broadcast_key );

	return queue_message( mysql, from_user, to_identity, buf );
}

long send_forward_to( MYSQL *mysql, const char *from_user, const char *to_identity, 
		int childNum, long long generation, const char *forwardToSite, const char *relid )
{
	static char buf[8192];

	sprintf( buf, 
		"forward_to %d %lld %s %s\r\n", 
		childNum, generation, forwardToSite, relid );

	return queue_message( mysql, from_user, to_identity, buf );
}

void prefriend_message( MYSQL *mysql, const char *relid, const char *msg )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	RSA *id_pub, *user_priv;
	Encrypt encrypt;
	int decrypt_res;
	const char *user, *friend_id;

	exec_query( mysql, 
		"SELECT from_user, for_id FROM sent_friend_request "
		"WHERE requested_relid = %e",
		relid );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 ) {
		message("prefriend_message: could not locate friend via sent_friend_request\n");
		BIO_printf( bioOut, "ERROR finding friend\r\n" );
		goto free_result;
	}

	user = row[0];
	friend_id = row[1];

	user_priv = load_key( mysql, user );
	id_pub = fetch_public_key( mysql, friend_id );

	encrypt.load( id_pub, user_priv );
	decrypt_res = encrypt.decryptVerify( msg );

	if ( decrypt_res < 0 ) {
		message("prefriend_message: decrypting message failed\n");
		BIO_printf( bioOut, "ERROR %s\r\n", encrypt.err );
		goto free_result;
	}

	prefriend_message_parser( mysql, relid, user, friend_id, (char*)encrypt.decrypted );

free_result:
	mysql_free_result( result );
	return;
}

void receive_message( MYSQL *mysql, const char *relid, const char *message )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	RSA *id_pub, *user_priv;
	Encrypt encrypt;
	int decrypt_res;
	const char *user, *friend_id;

	exec_query( mysql, 
		"SELECT user, friend_id FROM friend_claim "
		"WHERE get_relid = %e",
		relid );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 ) {
		BIO_printf( bioOut, "ERROR finding friend\r\n" );
		return;
	}
	user = row[0];
	friend_id = row[1];

	user_priv = load_key( mysql, user );
	id_pub = fetch_public_key( mysql, friend_id );

	encrypt.load( id_pub, user_priv );
	decrypt_res = encrypt.decryptVerify( message );

	if ( decrypt_res < 0 ) {
		BIO_printf( bioOut, "ERROR %s\r\n", encrypt.err );
		return;
	}

	int parseResult = message_parser( mysql, relid, user, friend_id, (char*)encrypt.decrypted );
	if ( parseResult < 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}
}

void login( MYSQL *mysql, const char *user, const char *pass )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	Encrypt encrypt;
	u_char token[RELID_SIZE];
	u_char pass_salt[SALT_SIZE];
	char *token_str;
	char *pass_hashed, *salt_str, *pass_str, *id_salt_str;
	long lasts = LOGIN_TOKEN_LASTS;
	char *identity, *id_hash_str;

	exec_query( mysql, 
		"SELECT user, pass_salt, pass, id_salt FROM user WHERE user = %e", user );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		goto free_result;
	}

	salt_str = row[1];
	pass_str = row[2];
	id_salt_str = row[3];

	base64_to_bin( pass_salt, 0, salt_str );
	message("pass_salt_str: %s\n", bin2hex( pass_salt, SALT_SIZE ) );
	message("pass: %s\n", pass );

	/* Hash the password. */
	pass_hashed = pass_hash( pass_salt, pass );

	if ( strcmp( pass_hashed, pass_str ) != 0 ) {
		message("pass hashes do not match %s %s\n", pass_hashed, pass_str );
		BIO_printf( bioOut, "ERROR\r\n" );
		goto free_result;
	}

	RAND_bytes( token, TOKEN_SIZE );
	token_str = bin_to_base64( token, TOKEN_SIZE );

	exec_query( mysql, 
		"INSERT INTO login_token ( user, login_token, expires ) "
		"VALUES ( %e, %e, date_add( now(), interval %l second ) )", user, token_str, lasts );

	identity = new char[strlen(c->CFG_URI) + strlen(user) + 2];
	sprintf( identity, "%s%s/", c->CFG_URI, user );
	id_hash_str = make_id_hash( id_salt_str, identity );

	BIO_printf( bioOut, "OK %s %s %ld\r\n", id_hash_str, token_str, lasts );

free_result:
	mysql_free_result( result );
}

void submit_ftoken( MYSQL *mysql, const char *token )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	long lasts = LOGIN_TOKEN_LASTS;
	char *user, *from_id, *hash;

	exec_query( mysql,
		"SELECT user, from_id FROM ftoken_request WHERE token = %e",
		token );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		goto free_result;
	}
	user = row[0];
	from_id = row[1];

	exec_query( mysql, 
		"INSERT INTO flogin_token ( user, identity, login_token, expires ) "
		"VALUES ( %e, %e, %e, date_add( now(), interval %l second ) )", 
		user, from_id, token, lasts );

	exec_query( mysql,
		"SELECT friend_hash FROM friend_claim WHERE friend_id = %e", from_id );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		goto free_result;
	}
	hash = row[0];

	BIO_printf( bioOut, "OK %s %ld %s\r\n", hash, lasts, from_id );

free_result:
	mysql_free_result( result );
}

void encrypt_remote_broadcast( MYSQL *mysql, const char *user,
		const char *subject_id, const char *token, long long seq_num,
		const char *type, const char *msg )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	Encrypt encrypt;
	RSA *user_priv, *id_pub;
	int sigRes;
	String broadcast_key;
	long long generation;
	char *authorId;
	char *full;
	long soFar;
	time_t curTime;
	struct tm curTM, *tmRes;
	char time_str[64];

	long mLen = strlen(msg);

	message( "entering encrypt_remote_broadcast( %s, %s, %s )\n", user, subject_id, token );

	message( "encrypt_remote_broadcast submitted token: %s\n", token );

	exec_query( mysql,
		"SELECT user FROM remote_flogin_token "
		"WHERE user = %e AND identity = %e AND login_token = %e",
		user, subject_id, token );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 ) {
		message("failed to find user from provided login token\n");
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}

	/* Get the current time. */
	curTime = time(NULL);

	/* Convert to struct tm. */
	tmRes = localtime_r( &curTime, &curTM );
	if ( tmRes == 0 ) {
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}

	/* Format for the message. */
	if ( strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &curTM )  == 0 )  {
		BIO_printf( bioOut, "ERROR\r\n" );
		return;
	}

	authorId = new char[strlen(c->CFG_URI) + strlen(user) + 2];
	sprintf( authorId, "%s%s/", c->CFG_URI, user );

	user_priv = load_key( mysql, user );
	id_pub = fetch_public_key( mysql, subject_id );

	exec_query( mysql,
		"INSERT INTO remote_published "
		"( user, author_id, subject_id, time_published, type, message ) "
		"VALUES ( %e, %e, %e, now(), %e, %d )",
		user, authorId, subject_id, type, msg, mLen );

	::message( "encrypt_remote_broadcast type: %s\n", type );
	
	/* Find current generation and youngest broadcast key */
	current_put_bk( mysql, user, generation, broadcast_key );

	/* Make the full message. */
	full = new char[128+mLen];
	soFar = sprintf( full, "remote_inner %lld %s %s %ld\r\n", seq_num, time_str, type, mLen );
	memcpy( full + soFar, msg, mLen );
	full[soFar+mLen] = 0;

	encrypt.load( id_pub, user_priv );
	sigRes = encrypt.bkSignEncrypt( broadcast_key, (u_char*)full, soFar+mLen );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}

	message( "encrypt_remote_broadcast enc: %s\n", encrypt.sym );
	String resultCmd( "encrypted_broadcast %lld %s\r\n", generation, encrypt.sym );

	encrypt.signEncrypt( (u_char*)resultCmd.data, resultCmd.length+1 );

	BIO_printf( bioOut, "RESULT %d\r\n", strlen(encrypt.sym) );
	BIO_write( bioOut, encrypt.sym, strlen(encrypt.sym) );
}

char *decrypt_result( MYSQL *mysql, const char *from_user, 
		const char *to_identity, const char *user_message )
{
	RSA *id_pub, *user_priv;
	Encrypt encrypt;
	int decrypt_res;

	::message( "decrypting result %s %s %s\n", from_user, to_identity, user_message );

	user_priv = load_key( mysql, from_user );
	id_pub = fetch_public_key( mysql, to_identity );

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

long notify_accept( MYSQL *mysql, const char *for_user, const char *from_id,
		const char *id_salt, const char *requested_relid, const char *returned_relid )
{
	RSA *id_pub, *user_priv;
	Encrypt encrypt;
	MYSQL_RES *result;
	MYSQL_ROW row;
	char *returned_id_salt;

	/* Verify that there is a friend request. */
	DbQuery checkSentRequest( mysql, 
		"SELECT from_user FROM sent_friend_request "
		"WHERE from_user = %e AND for_id = %e AND requested_relid = %e and returned_relid = %e",
		for_user, from_id, requested_relid, returned_relid );

	if ( checkSentRequest.rows() != 1 ) {
		message("accept friendship failed: could not find send_friend_request\r\n");
		BIO_printf( bioOut, "ERROR request not found\r\n");
		return 0;
	}

	user_priv = load_key( mysql, for_user );
	id_pub = fetch_public_key( mysql, from_id );

	/* The relid is the one we made on this end. It becomes the put_relid. */
	store_friend_claim( mysql, for_user, from_id, id_salt, returned_relid, requested_relid );

	/* Clear the sent_freind_request. */
	exec_query( mysql, "SELECT id_salt FROM user WHERE user = %e", for_user );

	/* Check for a result. */
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		BIO_printf( bioOut, "ERROR request not found\r\n" );
		return 0;
	}
	returned_id_salt = row[0];

	String resultCommand( "returned_id_salt %s\r\n", returned_id_salt );

	encrypt.load( id_pub, user_priv );
	encrypt.signEncrypt( (u_char*)resultCommand.data, resultCommand.length+1 );

	BIO_printf( bioOut, "RESULT %d\r\n", strlen(encrypt.sym) );
	BIO_write( bioOut, encrypt.sym, strlen(encrypt.sym) );

	return 0;
}

long registered( MYSQL *mysql, const char *for_user, const char *from_id,
		const char *requested_relid, const char *returned_relid )
{
	::message("registered: starting\n");

	forward_tree_insert( mysql, for_user, from_id, returned_relid );

	DbQuery removeSentRequest( mysql, 
		"DELETE FROM sent_friend_request "
		"WHERE from_user = %e AND for_id = %e AND requested_relid = %e AND "
		"	returned_relid = %e",
		for_user, from_id, requested_relid, returned_relid );

	BIO_printf( bioOut, "OK\r\n" );

	::message("registered: finished\n");

	return 0;
}
