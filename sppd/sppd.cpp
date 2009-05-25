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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define LOGIN_TOKEN_LASTS 86400

void set_config_by_uri( const char *uri )
{
	c = config_first;
	while ( c != 0 && strcmp( c->CFG_URI, uri ) != 0 )
		c = c->next;

	if ( c == 0 ) {
		fprintf(stderr, "bad site\n");
		exit(1);
	}
}

void set_config_by_name( const char *name )
{
	c = config_first;
	while ( c != 0 && strcmp( c->name, name ) != 0 )
		c = c->next;

	if ( c == 0 ) {
		fprintf(stderr, "bad site\n");
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


char *pass_hash( const char *user, const char *pass )
{
	unsigned char pass_bin[MD5_DIGEST_LENGTH];
	char pass_comb[1024];
	sprintf( pass_comb, "%s:spp:%s", user, pass );
	MD5( (unsigned char*)pass_comb, strlen(pass_comb), pass_bin );
	return bin2hex( pass_bin, MD5_DIGEST_LENGTH );
}

int current_put_sk( MYSQL *mysql, const char *user, char *sk, long long *generation )
{
	int retVal = 0;

	exec_query( mysql, 
		"SELECT session_key, generation "
		"FROM put_session_key "
		"WHERE user = %e "
		"ORDER BY generation DESC LIMIT 1",
		user );
	
	MYSQL_RES *result = mysql_store_result( mysql );
	MYSQL_ROW row = mysql_fetch_row( result );

	if ( row ) {
		if ( sk != 0 ) 
			strcpy( sk, row[0] );
		if ( generation != 0 )
			*generation = strtoll( row[1], 0, 10 );
		retVal = 1;
	}

	return retVal;
}

void new_session_key( MYSQL *mysql, const char *user )
{
	unsigned char session_key[RELID_SIZE];
	const char *sk = 0;
	long long generation = 0;

	/* Get the latest generation. If there is no session key then generation
	 * is left alone. */
	current_put_sk( mysql, user, 0, &generation );

	/* Generate the relationship and request ids. */
	RAND_bytes( session_key, RELID_SIZE );
	sk = bin2hex( session_key, RELID_SIZE );

	exec_query( mysql, 
		"INSERT INTO put_session_key "
		"( user, session_key, generation ) "
		"VALUES ( %e, %e, %L ) ",
		user, sk, generation + 1 );
}

bool check_comm_key( const char *key )
{
	return true;
}

void new_user( MYSQL *mysql, const char *user, const char *pass, const char *email )
{
	char *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	RSA *rsa;
	char *pass_hashed;

	/* Generate a new key. */
	rsa = RSA_generate_key( 1024, RSA_F4, 0, 0 );
	if ( rsa == 0 ) {
		printf( "ERROR key generation failed\r\n");
		goto flush;
	}

	/* Extract the components to hex strings. */
	n = BN_bn2hex( rsa->n );
	e = BN_bn2hex( rsa->e );
	d = BN_bn2hex( rsa->d );
	p = BN_bn2hex( rsa->p );
	q = BN_bn2hex( rsa->q );
	dmp1 = BN_bn2hex( rsa->dmp1 );
	dmq1 = BN_bn2hex( rsa->dmq1 );
	iqmp = BN_bn2hex( rsa->iqmp );

	/* Hash the password. */
	pass_hashed = pass_hash( user, pass );

	/* Execute the insert. */
	exec_query( mysql, "INSERT INTO user VALUES("
		"%e, %e, %e, %e, %e, %e, %e, %e, %e, %e, %e);", 
		user, pass_hashed, email, n, e, d, p, q, dmp1, dmq1, iqmp );
	
	/* Make the first session key for the user. */
	new_session_key( mysql, user );

	printf( "OK\r\n" );

	OPENSSL_free( n );
	OPENSSL_free( e );
	OPENSSL_free( d );
	OPENSSL_free( p );
	OPENSSL_free( q );
	OPENSSL_free( dmp1 );
	OPENSSL_free( dmq1 );
	OPENSSL_free( iqmp );

	RSA_free( rsa );
flush:
	fflush( stdout );
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
		printf( "ERROR user not found\r\n" );
		goto free_result;
	}

	/* Everythings okay. */
	printf( "OK %s/%s\n", row[0], row[1] );

free_result:
	mysql_free_result( result );

	fflush(stdout);
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
	BN_hex2bn( &rsa->n, pub.n );
	BN_hex2bn( &rsa->e, pub.e );

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
	BN_hex2bn( &rsa->n,    row[0] );
	BN_hex2bn( &rsa->e,    row[1] );
	BN_hex2bn( &rsa->d,    row[2] );
	BN_hex2bn( &rsa->p,    row[3] );
	BN_hex2bn( &rsa->q,    row[4] );
	BN_hex2bn( &rsa->dmp1, row[5] );
	BN_hex2bn( &rsa->dmq1, row[6] );
	BN_hex2bn( &rsa->iqmp, row[7] );

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
		printf( "ERROR %d\r\n", ERROR_FRIEND_CLAIM_EXISTS );
		goto close;
	}

	/* Check for the existence of a friend request. */
	if ( friend_request_exists( mysql, user, identity ) ) {
		printf( "ERROR %d\r\n", ERROR_FRIEND_REQUEST_EXISTS );
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity );
	if ( id_pub == 0 ) {
		printf( "ERROR %d\n", ERROR_PUBLIC_KEY );
		goto close;
	}

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	/* Generate the relationship and request ids. */
	RAND_bytes( requested_relid, RELID_SIZE );
	RAND_bytes( fr_reqid, REQID_SIZE );

	/* Encrypt and sign the relationship id. */
	encrypt.load( id_pub, user_priv );
	sigRes = encrypt.encryptSign( requested_relid, RELID_SIZE );
	if ( sigRes < 0 ) {
		printf( "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		goto close;
	}
	
	/* Store the request. */
	requested_relid_str = bin2hex( requested_relid, RELID_SIZE );
	reqid_str = bin2hex( fr_reqid, REQID_SIZE );

	exec_query( mysql,
		"INSERT INTO relid_request "
		"( for_user, from_id, requested_relid, reqid, msg_enc, msg_sig ) "
		"VALUES( %e, %e, %e, %e, %e, %e )",
		user, identity, requested_relid_str, reqid_str, encrypt.enc, encrypt.sig );
	
	/* Return the request id for the requester to use. */
	printf( "OK %s\r\n", reqid_str );

	free( requested_relid_str );
	free( reqid_str );
close:
	fflush( stdout );
}

void fetch_requested_relid( MYSQL *mysql, const char *reqid )
{
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql,
		"SELECT msg_enc, msg_sig FROM relid_request WHERE reqid = %e", reqid );

	if ( query_res != 0 ) {
		printf("ERR\r\n");
		goto query_fail;
	}

	/* Check for a result. */
	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row )
		printf( "OK %s %s\r\n", row[0], row[1] );
	else
		printf( "ERROR\r\n" );

	/* Done. */
	mysql_free_result( select_res );

query_fail:
	fflush( stdout );
}

long store_relid_response( MYSQL *mysql, const char *identity, 
		const char *fr_relid_str, const char *fr_reqid_str, 
		const char *relid_str, const char *reqid_str, 
		const char *enc, const char *sig )
{
	int result = exec_query( mysql,
		"INSERT INTO relid_response "
		"( from_id, requested_relid, returned_relid, reqid, msg_enc, msg_sig ) "
		"VALUES ( %e, %e, %e, %e, %e, %e )",
		identity, fr_relid_str, relid_str, 
		reqid_str, enc, sig );
	
	return result;
}

long store_friend_claim( MYSQL *mysql, const char *user, 
		const char *identity, const char *put_relid, const char *get_relid, 
		bool acknowledged )
{
	/* Make an md5hash for the identity. */
	unsigned char friend_hash[MD5_DIGEST_LENGTH];
	MD5( (unsigned char*)identity, strlen(identity), friend_hash );
	char *friend_hash_str = bin2hex( friend_hash, MD5_DIGEST_LENGTH );

	/* Insert the friend claim. */
	exec_query( mysql, "INSERT INTO friend_claim "
		"( user, friend_id, friend_hash, put_relid, get_relid, acknowledged, put_root ) "
		"VALUES ( %e, %e, %e, %e, %e, %b, %b );",
		user, identity, friend_hash_str, put_relid, get_relid, acknowledged, false );

	return 0;
}

void relid_response( MYSQL *mysql, const char *user, const char *fr_reqid_str,
		const char *identity, const char *id_host, const char *id_user )
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
	char *site;
	Encrypt encrypt;

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity );
	if ( id_pub == 0 ) {
		printf( "ERROR %d\r\n", ERROR_PUBLIC_KEY );
		goto close;
	}

	site = get_site( identity );

	RelidEncSig encsig;
	fetchRes = fetch_requested_relid_net( encsig, site, id_host, fr_reqid_str );
	if ( fetchRes < 0 ) {
		printf( "ERROR %d\r\n", ERROR_FETCH_REQUESTED_RELID );
		goto close;
	}

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	/* Decrypt and verify the requested_relid. */
	encrypt.load( id_pub, user_priv );

	verifyRes = encrypt.decryptVerify( encsig.enc, encsig.sig );
	if ( verifyRes < 0 ) {
		printf( "ERROR %d\r\n", ERROR_DECRYPT_VERIFY );
		goto close;
	}

	/* Verify the message is the right size. */
	if ( encrypt.decLen != RELID_SIZE ) {
		printf( "ERROR %d\r\n", ERROR_DECRYPTED_SIZE );
		goto close;
	}

	/* This should not be deleted as long as we don't do any more decryption. */
	requested_relid = encrypt.decrypted;
	
	/* Generate the relationship and request ids. */
	RAND_bytes( response_relid, RELID_SIZE );
	RAND_bytes( response_reqid, REQID_SIZE );

	memcpy( message, requested_relid, RELID_SIZE );
	memcpy( message+RELID_SIZE, response_relid, RELID_SIZE );

	/* Encrypt and sign using the same credentials. */
	sigRes = encrypt.encryptSign( message, RELID_SIZE*2 );
	if ( sigRes < 0 ) {
		printf( "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		goto close;
	}

	/* Store the request. */
	requested_relid_str = bin2hex( requested_relid, RELID_SIZE );
	response_relid_str = bin2hex( response_relid, RELID_SIZE );
	response_reqid_str = bin2hex( response_reqid, REQID_SIZE );

	store_relid_response( mysql, identity, requested_relid_str, fr_reqid_str, 
			response_relid_str, response_reqid_str,
			encrypt.enc, encrypt.sig );

	/* The relid is the one we made on this end. It becomes the put_relid. */
	store_friend_claim( mysql, user, identity, response_relid_str, requested_relid_str, false );
	
	/* Return the request id for the requester to use. */
	printf( "OK %s\r\n", response_reqid_str );

	free( requested_relid_str );
	free( response_relid_str );
	free( response_reqid_str );

close:
	fflush( stdout );
}

void fetch_response_relid( MYSQL *mysql, const char *reqid )
{
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	/* Execute the query. */
	query_res = exec_query( mysql,
		"SELECT msg_enc, msg_sig FROM relid_response WHERE reqid = %e;", reqid );
	
	if ( query_res != 0 ) {
		printf("ERR\r\n");
		goto query_fail;
	}

	/* Check for a result. */
	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row )
		printf( "OK %s %s\r\n", row[0], row[1] );
	else
		printf( "ERR\r\n" );

	/* Done. */
	mysql_free_result( select_res );

query_fail:
	fflush( stdout );
}

long verify_returned_fr_relid( MYSQL *mysql, unsigned char *fr_relid )
{
	long result = 0;
	char *requested_relid_str = bin2hex( fr_relid, RELID_SIZE );
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
	fflush(stdout);
	return result;
}

void friend_final( MYSQL *mysql, const char *user, const char *reqid_str, const char *identity, 
		const char *id_host, const char *id_user )
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
	char *site;
	Encrypt encrypt;

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity );
	if ( id_pub == 0 ) {
		printf( "ERROR %d\r\n", ERROR_PUBLIC_KEY );
		goto close;
	}

	site = get_site( identity );

	RelidEncSig encsig;
	fetchRes = fetch_response_relid_net( encsig, site, id_host, reqid_str );
	if ( fetchRes < 0 ) {
		printf( "ERROR %d\r\n", ERROR_FETCH_RESPONSE_RELID );
		goto close;
	}
	
	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	encrypt.load( id_pub, user_priv );

	verifyRes = encrypt.decryptVerify( encsig.enc, encsig.sig );
	if ( verifyRes < 0 ) {
		printf( "ERROR %d\r\n", ERROR_DECRYPT_VERIFY );
		goto close;
	}

	/* Verify that the message is the right size. */
	if ( encrypt.decLen != RELID_SIZE*2 ) {
		printf( "ERROR %d\r\n", ERROR_DECRYPTED_SIZE );
		goto close;
	}

	message = encrypt.decrypted;

	memcpy( requested_relid, message, RELID_SIZE );
	memcpy( returned_relid, message+RELID_SIZE, RELID_SIZE );

	verifyRes = verify_returned_fr_relid( mysql, requested_relid );
	if ( verifyRes != 1 ) {
		printf( "ERROR %d\r\n", ERROR_REQUESTED_RELID_MATCH );
		goto close;
	}
		
	requested_relid_str = bin2hex( requested_relid, RELID_SIZE );
	returned_relid_str = bin2hex( returned_relid, RELID_SIZE );

	/* Make a user request id. */
	RAND_bytes( user_reqid, REQID_SIZE );
	user_reqid_str = bin2hex( user_reqid, REQID_SIZE );

	exec_query( mysql, 
		"INSERT INTO friend_request "
		" ( for_user, from_id, reqid, requested_relid, returned_relid ) "
		" VALUES ( %e, %e, %e, %e, %e ) ",
		user, identity, user_reqid_str, requested_relid_str, returned_relid_str );
	
	/* Return the request id for the requester to use. */
	printf( "OK\r\n" );

	free( requested_relid_str );
	free( returned_relid_str );
close:
	fflush( stdout );
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
		"SELECT to_site, relid, sig, generation, message FROM broadcast_queue" );

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
		char *sig = row[2];
		long long generation = strtoll( row[3], 0, 10 );
		char *message = row[4];

		//printf( "%s %s %s\n", row[0], row[1], row[2] );
		long send_res = send_broadcast_net( to_site, relid, sig, generation, message );
		if ( send_res < 0 ) {
			printf("ERROR trouble sending message: %ld\n", send_res);
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
				char *sig = row[2];
				char *generation = row[3];
				char *message = row[4];

				printf("Putting back to the queue: %s %s %s\n", row[0], row[1], row[2] );

				/* Queue the message. */

				exec_query( mysql,
					"INSERT INTO broadcast_queue "
					"( to_site, relid, sig, generation, message ) "
					"VALUES ( %e, %e, %e, %e, %e ) ",
					to_site, relid, sig, generation, message );
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
		"SELECT to_id, relid, enc, sig, message FROM message_queue" );

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

		char *to_id = row[0];
		char *relid = row[1];
		char *enc = row[2];
		char *sig = row[3];
		char *message = row[4];

		//printf( "%s %s %s\n", row[0], row[1], row[2] );
		long send_res = send_message_net( to_id, relid, enc, sig, message );
		if ( send_res < 0 ) {
			printf("ERROR trouble sending message: %ld\n", send_res);
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

			char *to_id = row[0];
			char *relid = row[1];
			char *enc = row[2];
			char *sig = row[3];
			char *message = row[4];

			if ( !sent[i] ) {
				printf("Putting back to the queue: %s %s %s\n", row[0], row[1], row[2] );

				exec_query( mysql,
					"INSERT INTO message_queue "
					"( to_id, relid, enc, sig, message ) "
					"VALUES ( %e, %e, %e, %e, %e ) ",
					to_id, relid, enc, sig, message );
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
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	run_broadcast_queue_db( mysql );
	run_message_queue_db( mysql );

close:
	mysql_close( mysql );
	fflush( stdout );
}

int send_current_session_key( MYSQL *mysql, const char *user, const char *identity )
{
	char sk[SK_SIZE_HEX];
	long long generation;
	int sk_result;

	/* Get the latest put session key. */
	sk_result = current_put_sk( mysql, user, sk, &generation );
	if ( sk_result != 1 ) {
		printf( "ERROR fetching session key\r\n");
	}

	int send_res = send_session_key( mysql, user, identity, sk, generation );
	if ( send_res < 0 ) {
		fprintf(stderr, "sending failed %d\n", send_res );
	}

	return 0;
}

void accept_friend( MYSQL *mysql, const char *user, const char *user_reqid )
{
	MYSQL_RES *result;
	MYSQL_ROW row;

	/* Execute the query. */
	exec_query( mysql, "SELECT from_id, requested_relid, returned_relid "
		"FROM friend_request "
		"WHERE for_user = %e AND reqid = %e;",
		user, user_reqid );

	/* Check for a result. */
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		printf( "ERROR request not found\r\n" );
		goto close;
	}

	/* The friendship has been accepted. Store the claim. The fr_relid is the
	 * one that we made on this end. It becomes the put_relid. */
	store_friend_claim( mysql, user, row[0], row[1], row[2], true );

	/* Remove the user friend request. */
	delete_friend_request( mysql, user, user_reqid );

	send_current_session_key( mysql, user, row[0] );
	forward_tree_insert( mysql, user, row[0], row[1] );

	printf( "OK\r\n" );

	mysql_free_result( result );
close:
	fflush( stdout );
}


long store_ftoken( MYSQL *mysql, const char *user, 
		const char *identity, char *token_str, char *reqid_str,
		char *msg_enc, char *msg_sig )
{
	long result = 0;
	int query_res;

	query_res = exec_query( mysql,
		"INSERT INTO ftoken_request "
		"( user, from_id, token, reqid, msg_enc, msg_sig ) "
		"VALUES ( %e, %e, %e, %e, %e, %e ) ",
		user, identity, token_str, reqid_str, msg_enc, msg_sig );

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
		/* No friend claim ... send back a reqid anyways. Don't want to give
		 * away that there is no claim. FIXME: Would be good to fake this with
		 * an appropriate time delay. */
		RAND_bytes( reqid, RELID_SIZE );
		reqid_str = bin2hex( reqid, RELID_SIZE );
		printf( "OK %s\r\n", reqid_str );
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, friend_id.identity );
	if ( id_pub == 0 ) {
		printf("ERROR %d\r\n", ERROR_PUBLIC_KEY );
		goto close;
	}

	/* Load the private key for the user. */
	user_priv = load_key( mysql, user );

	/* Generate the login request id and relationship and request ids. */
	RAND_bytes( flogin_token, TOKEN_SIZE );
	RAND_bytes( reqid, REQID_SIZE );

	encrypt.load( id_pub, user_priv );

	/* Encrypt it. */
	sigRes = encrypt.encryptSign( flogin_token, TOKEN_SIZE );
	if ( sigRes < 0 ) {
		printf( "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		goto close;
	}

	/* Store the request. */
	flogin_token_str = bin2hex( flogin_token, TOKEN_SIZE );
	reqid_str = bin2hex( reqid, REQID_SIZE );

	store_ftoken( mysql, user, friend_id.identity, 
			flogin_token_str, reqid_str, encrypt.enc, encrypt.sig );
	
	/* Return the request id for the requester to use. */
	printf( "OK %s\r\n", reqid_str );

	free( flogin_token_str );
	free( reqid_str );

close:
	fflush( stdout );
}

void fetch_ftoken( MYSQL *mysql, const char *reqid )
{
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	query_res = exec_query( mysql,
		"SELECT msg_enc, msg_sig FROM ftoken_request WHERE reqid = %e", reqid );

	/* Execute the query. */
	if ( query_res != 0 ) {
		printf( "ERROR %d\r\n", ERROR_DB_ERROR );
		goto query_fail;
	}

	/* Check for a result. */
	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row )
		printf( "OK %s %s\r\n", row[0], row[1] );
	else
		printf( "ERROR %d\r\n", ERROR_NO_FTOKEN );

	/* Done. */
	mysql_free_result( select_res );

query_fail:
	fflush( stdout );
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

	/* Check if this identity is our friend. */
	friend_claim = check_friend_claim( friend_id, mysql, user, hash );
	if ( friend_claim <= 0 ) {
		/* No friend claim ... we can reveal this since ftoken_response requires
		 * that the user be logged in. */
		printf( "ERROR %d\r\n", ERROR_NOT_A_FRIEND );
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, friend_id.identity );
	if ( id_pub == 0 ) {
		printf("ERROR %d\r\n", ERROR_PUBLIC_KEY );
		goto close;
	}

	site = get_site( friend_id.identity );

	RelidEncSig encsig;
	fetchRes = fetch_ftoken_net( encsig, site, friend_id.host, flogin_reqid_str );
	if ( fetchRes < 0 ) {
		printf("ERROR %d\r\n", ERROR_FETCH_FTOKEN );
		goto close;
	}

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	encrypt.load( id_pub, user_priv );

	/* Decrypt the flogin_token. */
	verifyRes = encrypt.decryptVerify( encsig.enc, encsig.sig );
	if ( verifyRes < 0 ) {
		printf( "ERROR %d\r\n", ERROR_DECRYPT_VERIFY );
		goto close;
	}

	/* Check the size. */
	if ( encrypt.decLen != REQID_SIZE ) {
		printf( "ERROR %d\r\n", ERROR_DECRYPTED_SIZE );
		goto close;
	}

	flogin_token = encrypt.decrypted;
	flogin_token_str = bin2hex( flogin_token, RELID_SIZE );

	/* Return the login token for the requester to use. */
	printf( "OK %s\r\n", flogin_token_str );

	free( flogin_token_str );
close:
	fflush( stdout );
}

/* Check if we have an acknowledment of a friend claim. */
bool is_acknowledged( MYSQL *mysql, const char *user, const char *identity )
{
	exec_query( mysql, 
		"SELECT acknowledged "
		"FROM friend_claim "
		"WHERE user = %e AND friend_id = %e",
		user, identity );
	
	MYSQL_RES *result = mysql_store_result( mysql );
	MYSQL_ROW row = mysql_fetch_row( result );

	if ( row ) {
		int b = atoi( row[0] );
		if ( b )
			return true;
	}

	return false;
}

void session_key( MYSQL *mysql, const char *relid, const char *user,
		const char *identity, const char *sk, const char *generation )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	RSA *user_priv, *id_pub;
	long query_res;
	bool acknowledged;

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity );
	if ( id_pub == 0 ) {
		printf("ERROR fetch_public_key failed\n" );
		return;
	}

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	/* Make the query. */
	query_res = exec_query( mysql, 
			"INSERT INTO get_session_key "
			"( get_relid, session_key, generation ) "
			"VALUES ( %e, %e, %e ) ",
			relid, sk, generation );
	
	/* If this friend claim hasn't been acknowledged then send back
	 * a session key and acknowledge the claim. */
	acknowledged = is_acknowledged( mysql, user, identity );
	if ( !acknowledged ) {
		exec_query( mysql, 
			"UPDATE friend_claim SET acknowledged = true "
			"WHERE user = %e AND friend_id = %e",
			user, identity );

		exec_query( mysql, 
			"SELECT put_relid from friend_claim "
			"WHERE user = %e AND friend_id = %e",
			user, identity );

		result = mysql_store_result( mysql );
		row = mysql_fetch_row( result );

		send_current_session_key( mysql, user, identity );
		forward_tree_insert( mysql, user, identity, row[0] );
	}
	
	printf("OK\n");
}

void forward_to( MYSQL *mysql, const char *user, const char *identity,
		const char *number, const char *to_identity, const char *relid )
{
	if ( atoi( number ) == 1 ) {
		exec_query( mysql, 
				"UPDATE friend_claim "
				"SET get_fwd_site1 = %e, get_fwd_relid1 = %e "
				"WHERE user = %e AND friend_id = %e",
				to_identity, relid, user, identity );
	}
	else if ( atoi( number ) == 2 ) {
		exec_query( mysql, 
				"UPDATE friend_claim "
				"SET get_fwd_site2 = %e, get_fwd_relid2 = %e "
				"WHERE user = %e AND friend_id = %e",
				to_identity, relid, user, identity );
	}

	printf("OK\n");
}

long queue_broadcast_db( MYSQL *mysql, const char *to_site, const char *relid,
		const char *sig, long long generation, const char *message )
{
	/* Table lock. */
	exec_query( mysql, "LOCK TABLES broadcast_queue WRITE");

	exec_query( mysql,
		"INSERT INTO broadcast_queue "
		"( to_site, relid, sig, generation, message ) "
		"VALUES ( %e, %e, %e, %L, %e ) ",
		to_site, relid, sig, generation, message );

	/* UNLOCK reset. */
	exec_query( mysql, "UNLOCK TABLES");

	return 0;
}

long queue_message_db( MYSQL *mysql, const char *to_identity, const char *relid,
		const char *enc, const char *sig, const char *message )
{
	/* Table lock. */
	exec_query( mysql, "LOCK TABLES message_queue WRITE");

	exec_query( mysql,
		"INSERT INTO message_queue "
		"( to_id, relid, enc, sig, message ) "
		"VALUES ( %e, %e, %e, %e, %e ) ",
		to_identity, relid, enc, sig, message );

	/* UNLOCK reset. */
	exec_query( mysql, "UNLOCK TABLES");
	
	return 0;
}

long submit_fbroadcast( MYSQL *mysql, const char *to_identity, 
		const char *from_identity, const char *user_message )
{
	Identity to( to_identity );
	to.parse();
	send_remote_publish_net( from_identity, to_identity, user_message );
	connect_send_broadcast( mysql, to.user, user_message );
	return 0;
}

long connect_send_broadcast( MYSQL *mysql, const char *user, const char *user_message )
{
	time_t curTime;
	struct tm curTM, *tmRes;

	long messageLen;
	char *full;
	char timeStr[64];
	long sendResult;
	long long seq_id;
	MYSQL_RES *result;
	MYSQL_ROW row;

	/* Get the current time. */
	curTime = time(NULL);

	/* Convert to struct tm. */
	tmRes = localtime_r( &curTime, &curTM );
	if ( tmRes == 0 ) {
		printf("ERROR time error\r\n");
		goto close;
	}

	/* Format for the message. */
	if ( strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &curTM )  == 0) {
		printf("ERROR time error\r\n");
		goto close;
	}

	/* Insert the broadcast message into the published table. */
	exec_query( mysql,
		"INSERT INTO published "
		"( user, time_published, message ) "
		"VALUES ( %e, %e, %e )",
		user, timeStr, user_message );

	/* Get the id that was assigned to the message. */
	exec_query( mysql, "SELECT LAST_INSERT_ID()" );
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		printf("ERROR\r\n");
		goto close;
	}
	seq_id = strtoll( row[0], 0, 10 );

	/* Make the full message. */
	messageLen = strlen( user_message );
	full = new char[64+messageLen];
	sprintf( full, "%lld %s %s", seq_id, timeStr, user_message );

	sendResult = send_broadcast( mysql, user, full );
	if ( sendResult < 0 ) {
		printf("ERROR\r\n");
		goto close;
	}

	printf("OK\r\n");

close:
	fflush(stdout);
	return 0;
}

long send_broadcast( MYSQL *mysql, const char *user, const char *message )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	Encrypt encrypt;
	RSA *user_priv;
	char *session_key, *generation;
	char *friend_id, *put_relid;
	Identity id;

	/* Find youngest session key. In the future some sense of current session
	 * key should be maintained. */
	exec_query( mysql,
		"SELECT session_key, generation FROM put_session_key "
		"WHERE user = %e "
		"ORDER BY generation DESC "
		"LIMIT 1",
		user );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		printf("ERROR bad user\r\n");
		goto close;
	}
	session_key = strdup(row[0]);
	generation = strdup(row[1]);

	/* Find root user. */
	exec_query( mysql,
		"SELECT friend_id, put_relid FROM friend_claim "
		"WHERE user = %e AND put_root = true",
		user );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		/* Nothing here means that the user has no friends. */
	}
	else {
		friend_id = row[0];
		put_relid = row[1];

		/* Do the encryption. */
		user_priv = load_key( mysql, user );
		encrypt.load( 0, user_priv );
		encrypt.skEncryptSign( session_key, (u_char*)message, strlen(message)+1 );

		/* Find the root user to send to. */
		id.load( friend_id );
		id.parse();

		queue_broadcast_db( mysql, id.site, put_relid, encrypt.sig,
				strtoll(generation, 0, 10), encrypt.sym );
	}

close:
	return 0;
}

void receive_broadcast( MYSQL *mysql, const char *relid, const char *sig,
		long long key_generation, const char *message )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	char *user, *friend_id, *session_key;
	char *get_fwd_site1, *get_fwd_relid1;
	char *get_fwd_site2, *get_fwd_relid2;
	RSA *id_pub;
	Encrypt encrypt;
	int decryptRes;

	exec_query( mysql, 
		"SELECT friend_claim.user, friend_claim.friend_id, "
		"    get_fwd_site1, get_fwd_relid1, get_fwd_site2, get_fwd_relid2, "
		"    session_key "
		"FROM friend_claim "
		"JOIN get_session_key "
		"ON friend_claim.get_relid = get_session_key.get_relid "
		"WHERE friend_claim.get_relid = %e AND generation = %L",
		relid, key_generation );
	
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		printf("ERROR bad recipient\r\n");
		goto close;
	}

	user = row[0];
	friend_id = row[1];
	get_fwd_site1 = row[2];
	get_fwd_relid1 = row[3];
	get_fwd_site2 = row[4];
	get_fwd_relid2 = row[5];
	session_key = row[6];

	/* Do the decryption. */
	id_pub = fetch_public_key( mysql, friend_id );
	encrypt.load( id_pub, 0 );
	decryptRes = encrypt.skDecryptVerify( session_key, sig, message );

	if ( decryptRes < 0 ) {
		printf("ERROR\r\n");
		goto close;
	}

	store_message( mysql, relid, (char*)encrypt.decrypted );

	/* 
	 * Now do the forwarding.
	 */

	if ( get_fwd_site1 != 0 ) {
		queue_broadcast_db( mysql, get_fwd_site1, get_fwd_relid1, sig, 
				key_generation, message );
	}

	if ( get_fwd_site2 != 0 ) {
		queue_broadcast_db( mysql, get_fwd_site2, get_fwd_relid2, sig,
				key_generation, message );
	}

	mysql_free_result( result );

	printf("OK\n");

close:
	fflush(stdout);
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
	encrypt_res = encrypt.symEncryptSign( (u_char*)message, strlen(message)+1 );

	queue_message_db( mysql, to_identity, relid, encrypt.enc, encrypt.sig, encrypt.sym );
free_result:
	mysql_free_result( result );
	return 0;
}

long send_session_key( MYSQL *mysql, const char *from_user, const char *to_identity, 
		const char *session_key, long long generation )
{
	static char buf[8192];

	sprintf( buf,
		"session_key %s %lld\r\n", 
		session_key, generation );

	return queue_message( mysql, from_user, to_identity, buf );
}

long send_forward_to( MYSQL *mysql, const char *from_user, const char *to_identity, 
		int childNum, const char *forwardToSite, const char *relid )
{
	static char buf[8192];

	sprintf( buf, 
		"forward_to %d %s %s\r\n", 
		childNum, forwardToSite, relid );

	return queue_message( mysql, from_user, to_identity, buf );
}

void receive_message( MYSQL *mysql, const char *relid, const char *enc,
		const char *sig, const char *message )
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
	if ( row == 0 )
		goto free_result;
	user = row[0];
	friend_id = row[1];

	user_priv = load_key( mysql, user );
	id_pub = fetch_public_key( mysql, friend_id );

	encrypt.load( id_pub, user_priv );
	decrypt_res = encrypt.symDecryptVerify( enc, sig, message );

	if ( decrypt_res < 0 ) {
		printf( "ERROR %s", encrypt.err );
		goto free_result;
	}

	message_parser( mysql, relid, user, friend_id, (char*)encrypt.decrypted );

free_result:
	mysql_free_result( result );
	fflush( stdout );
	return;
}

void login( MYSQL *mysql, const char *user, const char *pass )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	Encrypt encrypt;
	unsigned char token[RELID_SIZE];
	char *token_str;
	char *pass_hashed;
	long lasts = LOGIN_TOKEN_LASTS;

	/* Hash the password. */
	pass_hashed = pass_hash( user, pass );

	exec_query( mysql, 
		"SELECT user FROM user WHERE user = %e AND pass = %e", user, pass_hashed );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 ) {
		printf("ERROR\r\n");
		goto free_result;
	}

	RAND_bytes( token, TOKEN_SIZE );
	token_str = bin2hex( token, TOKEN_SIZE );

	exec_query( mysql, 
		"INSERT INTO login_toks ( user, login_token, expires ) "
		"VALUES ( %e, %e, date_add( now(), interval %l second ) )", user, token_str, lasts );

	printf( "OK %s %ld\r\n", token_str, lasts );

free_result:
	mysql_free_result( result );
	fflush(stdout);
}

void submit_ftoken( MYSQL *mysql, const char *token )
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	long lasts = LOGIN_TOKEN_LASTS;

	exec_query( mysql,
		"SELECT from_id FROM ftoken_request WHERE token = %e",
		token );

	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( row == 0 ) {
		printf("ERROR\r\n");
		goto free_result;
	}

	printf( "OK %ld %s\r\n", lasts, row[0] );

free_result:
	mysql_free_result( result );
	fflush(stdout);
}

void remote_publish( MYSQL *mysql, const char *user,
		const char *identity, const char *user_message )
{
	exec_query( mysql,
		"INSERT INTO remote_published "
		"( user, identity, time_published, message ) "
		"VALUES ( %e, %e, now(), %e )",
		user, identity, user_message );
	
	printf( "OK\r\n" );

	fflush(stdout);
}
