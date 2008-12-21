/*
 * Copyright (c) 2008, Adrian Thurston <thurston@cs.queensu.ca>
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

#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "sppd.h"

char *strend( char *s )
{
	return s + strlen(s);
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

long hex2bin( unsigned char *dest, long len, char *src )
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

void new_user( const char *key, const char *user, const char *pass, const char *email )
{
	char *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	RSA *rsa;
	MYSQL *mysql, *connect_res;
	char *pass_hashed;
	char *query;
	long query_res;

	/* Check the authentication. */
	if ( strcmp( key, CFG_COMM_KEY ) != 0 ) {
		printf( "ERROR communication key invalid\r\n" );
		goto flush;
	}

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

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Hash the password. */
	pass_hashed = pass_hash( user, pass );

	/* Create the query. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "INSERT INTO user VALUES('" );
	mysql_real_escape_string( mysql, strend(query), user, strlen(user) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), pass_hashed, strlen(pass_hashed) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), email, strlen(email) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), n, strlen(n) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), e, strlen(e) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), d, strlen(d) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), p, strlen(p) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), q, strlen(q) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), dmp1, strlen(dmp1) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), dmq1, strlen(dmq1) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), iqmp, strlen(iqmp) );
	strcat( query, "' );" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
	if ( query_res != 0 ) {
		printf( "ERROR internal error: %s %d\r\n", __FILE__, __LINE__ );
		goto free_query;
	}

	printf( "OK\r\n" );

free_query:
	free( query );
close:
	OPENSSL_free( n );
	OPENSSL_free( e );
	OPENSSL_free( d );
	OPENSSL_free( p );
	OPENSSL_free( q );
	OPENSSL_free( dmp1 );
	OPENSSL_free( dmq1 );
	OPENSSL_free( iqmp );

	RSA_free( rsa );
	mysql_close( mysql );
flush:
	fflush( stdout );
}

void public_key( const char *user )
{
	MYSQL *mysql, *connect_res;
	char *query;
	long query_res;
	MYSQL_RES *result;
	MYSQL_ROW row;

	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "SELECT rsa_n, rsa_e FROM user WHERE user = '" );
	mysql_real_escape_string( mysql, strend(query), user, strlen(user) );
	strcat( query, "';" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
	if ( query_res != 0 ) {
		printf( "ERROR internal error: %s %d\r\n", __FILE__, __LINE__ );
		goto query_fail;
	}

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
query_fail:
	free( query );
close:
	mysql_close( mysql );
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
	char *query;
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "SELECT rsa_n, rsa_e FROM public_key WHERE identity = '" );
	mysql_real_escape_string( mysql, strend(query), identity, strlen(identity) );
	strcat( query, "';" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
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
	free( query );
	return result;
}

long store_public_key( MYSQL *mysql, const char *identity, PublicKey &pub )
{
	long result = 0, query_res;
	char *query;

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*3 );
	strcpy( query, "INSERT INTO public_key VALUES('" );
	mysql_real_escape_string( mysql, strend(query), identity, strlen(identity) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), pub.n, strlen(pub.n) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), pub.e, strlen(pub.e) );
	strcat( query, "' );" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
	if ( query_res != 0 ) {
		result = ERR_QUERY_ERROR;
		goto query_fail;
	}

query_fail:
	free( query );
	return result;
}

RSA *fetch_public_key( MYSQL *mysql, const char *identity, 
		const char *host, const char *user )
{
	PublicKey pub;
	RSA *rsa;

	/* First try to fetch the public key from the database. */
	long result = fetch_public_key_db( pub, mysql, identity );
	if ( result < 0 )
		return 0;

	/* If the db fetch failed, get the public key off the net. */
	if ( result == 0 ) {
		result = fetch_public_key_net( pub, host, user );
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
	char *query;
	long query_res;
	MYSQL_RES *result;
	MYSQL_ROW row;
	RSA *rsa;

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*1 );
	strcpy( query, "SELECT rsa_n, rsa_e, rsa_d, rsa_p, rsa_q, rsa_dmp1, rsa_dmq1, rsa_iqmp "
		"FROM user WHERE user = '" );
	mysql_real_escape_string( mysql, strend(query), user, strlen(user) );
	strcat( query, "';" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
	if ( query_res != 0 ) {
		goto query_fail;
	}

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
	free( query );
	return rsa;
}

long store_friend_req( MYSQL *mysql, const char *identity, char *fr_relid_str, 
		char *fr_reqid_str, unsigned char *encrypted, int enclen, 
		unsigned char *signature, int siglen )
{
	long result = 0;

	char *msg_enc = bin2hex( encrypted, enclen );
	char *msg_sig = bin2hex( signature, siglen );
	char *query = (char*)malloc( 1024 + 256*6 );

	/* Make the query. */
	strcpy( query, "INSERT INTO friend_req VALUES('" );
	mysql_real_escape_string( mysql, strend(query), identity, strlen(identity) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), fr_relid_str, strlen(fr_relid_str) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), fr_reqid_str, strlen(fr_reqid_str) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), msg_enc, strlen(msg_enc) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), msg_sig, strlen(msg_sig) );
	strcat( query, "' );" );

	/* Execute the query. */
	int query_res = mysql_query( mysql, query );
	if ( query_res != 0 )
		result = ERR_QUERY_ERROR;

	free( msg_enc );
	free( msg_sig );
	free( query );

	return result;
}


void friend_req( const char *user, const char *identity, 
		const char *id_host, const char *id_user )
{
	/* a) verifies challenge response
	 * b) fetches $URI/id.asc (using SSL)
	 * c) randomly generates a one-way relationship id ($FR-RELID)
	 * d) randomly generates a one-way request id ($FR-REQID)
	 * e) encrypts $FR-RELID to friender and signs it
	 * f) makes message available at $FR-URI/friend-request/$FR-REQID.asc
	 * g) redirects the user's browser to $URI/return-relid?uri=$FR-URI&reqid=$FR-REQID
	 */

	MYSQL *mysql, *connect_res;
	int sigres;
	RSA *user_priv, *id_pub;
	unsigned char fr_relid[RELID_SIZE], fr_reqid[REQID_SIZE];
	char *fr_relid_str, *fr_reqid_str;
	unsigned char *encrypted, *signature;
	int enclen;
	unsigned siglen;
	unsigned char relid_sha1[SHA_DIGEST_LENGTH];

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity, id_host, id_user );
	if ( id_pub == 0 ) {
		printf("ERROR fetch_public_key failed\n" );
		goto close;
	}

	/* Generate the relationship and request ids. */
	RAND_bytes( fr_relid, RELID_SIZE );
	RAND_bytes( fr_reqid, REQID_SIZE );
	
	/* Encrypt it. */
	encrypted = (unsigned char*)malloc( RSA_size(id_pub) );
	enclen = RSA_public_encrypt( RELID_SIZE, fr_relid, encrypted, 
			id_pub, RSA_PKCS1_PADDING );

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	/* Sign the relationship id. */
	signature = (unsigned char*)malloc( RSA_size(user_priv) );
	SHA1( fr_relid, RELID_SIZE, relid_sha1 );
	sigres = RSA_sign( NID_sha1, relid_sha1, SHA_DIGEST_LENGTH, signature, &siglen, user_priv );

	/* Store the request. */
	fr_relid_str = bin2hex( fr_relid, RELID_SIZE );
	fr_reqid_str = bin2hex( fr_reqid, REQID_SIZE );

	store_friend_req( mysql, identity, fr_relid_str, fr_reqid_str, 
			encrypted, enclen, signature, siglen );
	
	/* Return the request id for the requester to use. */
	printf( "OK %s\r\n", fr_reqid_str );

	free( fr_relid_str );
	free( fr_reqid_str );
close:
	mysql_close( mysql );
	fflush( stdout );
}

void fetch_fr_relid( const char *reqid )
{
	MYSQL *mysql, *connect_res;
	char *query;
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "SELECT msg_enc, msg_sig FROM friend_req WHERE fr_reqid = '" );
	mysql_real_escape_string( mysql, strend(query), reqid, strlen(reqid) );
	strcat( query, "';" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
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
	free( query );
close:
	mysql_close( mysql );
	fflush( stdout );
}

long store_return_relid( MYSQL *mysql, const char *identity, 
		const char *fr_relid_str, const char *fr_reqid_str, 
		const char *relid_str, const char *reqid_str, 
		unsigned char *encrypted, int enclen, unsigned char *signature, int siglen )
{
	long result = 0;

	char *msg_enc = bin2hex( encrypted, enclen );
	char *msg_sig = bin2hex( signature, siglen );
	char *query = (char*)malloc( 1024 + 256*6 );

	/* Make the query. */
	strcpy( query, "INSERT INTO return_relid VALUES('" );
	mysql_real_escape_string( mysql, strend(query), identity, strlen(identity) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), fr_relid_str, strlen(fr_relid_str) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), fr_reqid_str, strlen(fr_reqid_str) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), relid_str, strlen(relid_str) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), reqid_str, strlen(reqid_str) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), msg_enc, strlen(msg_enc) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), msg_sig, strlen(msg_sig) );
	strcat( query, "' );" );

	/* Execute the query. */
	int query_res = mysql_query( mysql, query );
	if ( query_res != 0 )
		result = ERR_QUERY_ERROR;

	free( msg_enc );
	free( msg_sig );
	free( query );

	return result;
}

long store_friend_claim( MYSQL *mysql, const char *user, 
		const char *identity, const char *put_relid, const char *get_relid )
{
	long result = 0;
	char *query = (char*)malloc( 1024 + 256*6 );

	/* Make an md5hash for the identity. */
	unsigned char friend_hash[MD5_DIGEST_LENGTH];
	MD5( (unsigned char*)identity, strlen(identity), friend_hash );
	char *friend_hash_str = bin2hex( friend_hash, MD5_DIGEST_LENGTH );

	/* Insert the friend claim. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "INSERT INTO friend_claim VALUES ( '" );
	mysql_real_escape_string( mysql, strend(query), user, strlen(user) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), identity, strlen(identity) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), friend_hash_str, strlen(friend_hash_str) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), put_relid, strlen(put_relid) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), get_relid, strlen(get_relid) );
	strcat( query, "');" );

	/* Execute the query. */
	int query_res = mysql_query( mysql, query );
	if ( query_res != 0 )
		result = ERR_QUERY_ERROR;

	free( query );
	return result;
}

void return_relid( const char *user, const char *fr_reqid_str, const char *identity, 
		const char *id_host, const char *id_user )
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

	MYSQL *mysql, *connect_res;
	int verifyres, fetchres, decryptres, sigres;
	RSA *user_priv, *id_pub;
	unsigned char *fr_relid;
	unsigned char *encrypted, *signature;
	int enclen;
	unsigned siglen;
	unsigned char relid_sha1[SHA_DIGEST_LENGTH];
	unsigned char relid[RELID_SIZE], reqid[REQID_SIZE];
	char *fr_relid_str, *relid_str, *reqid_str;
	unsigned char message[RELID_SIZE*2];

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity, id_host, id_user );
	if ( id_pub == 0 ) {
		printf("ERROR fetch_public_key failed\n" );
		goto close;
	}

	RelidEncSig encsig;
	fetchres = fetch_fr_relid_net( encsig, id_host, fr_reqid_str );
	if ( fetchres < 0 ) {
		printf("ERROR fetch_fr_relid failed %d\n", fetchres );
		goto close;
	}
	
	/* Convert the encrypted string to binary. */
	encrypted = (unsigned char*)malloc( strlen(encsig.enc) );
	enclen = hex2bin( encrypted, RSA_size(id_pub), encsig.enc );
	if ( enclen <= 0 ) {
		printf("ERROR converting encsig.enc to binary\n" );
		goto close;
	}

	/* Convert the sig to binary. */
	signature = (unsigned char*)malloc( strlen(encsig.sig) );
	siglen = hex2bin( signature, RSA_size(id_pub), encsig.sig );
	if ( siglen <= 0 ) {
		printf("ERROR converting encsig.sig to binary\n" );
		goto close;
	}

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	/* Decrypt the fr_relid. */
	fr_relid = (unsigned char*) malloc( RSA_size( user_priv ) );
	decryptres = RSA_private_decrypt( enclen, encrypted, fr_relid, user_priv, RSA_PKCS1_PADDING );
	if ( decryptres != REQID_SIZE ) {
		printf("ERROR failed to decrypt fr_reqid\n" );
		goto close;
	}

	/* Verify the fr_relid. */
	SHA1( fr_relid, RELID_SIZE, relid_sha1 );
	verifyres = RSA_verify( NID_sha1, relid_sha1, SHA_DIGEST_LENGTH, signature, siglen, id_pub );
	if ( verifyres != 1 ) {
		printf("ERROR failed to verify fr_reqid\n" );
		goto close;
	}

	/* Generate the relationship and request ids. */
	RAND_bytes( relid, RELID_SIZE );
	RAND_bytes( reqid, REQID_SIZE );

	memcpy( message, fr_relid, RELID_SIZE );
	memcpy( message+RELID_SIZE, relid, RELID_SIZE );

	/* Encrypt it. */
	enclen = RSA_public_encrypt( RELID_SIZE*2, message, encrypted, 
			id_pub, RSA_PKCS1_PADDING );

	/* Sign the relationship id. */
	SHA1( message, RELID_SIZE*2, relid_sha1 );
	sigres = RSA_sign( NID_sha1, relid_sha1, SHA_DIGEST_LENGTH, signature, &siglen, user_priv );

	/* Store the request. */
	fr_relid_str = bin2hex( fr_relid, RELID_SIZE );
	relid_str = bin2hex( relid, RELID_SIZE );
	reqid_str = bin2hex( reqid, REQID_SIZE );

	store_return_relid( mysql, identity, fr_relid_str, fr_reqid_str, 
			relid_str, reqid_str,
			encrypted, enclen, signature, siglen );

	/* The relid is the one we made on this end. It becomes the put_relid. */
	store_friend_claim( mysql, user, identity, relid_str, fr_relid_str );
	
	/* Return the request id for the requester to use. */
	printf( "OK %s\r\n", reqid_str );

	free( relid_str );
	free( reqid_str );
close:
	mysql_close( mysql );
	fflush( stdout );
}

void fetch_relid( const char *reqid )
{
	MYSQL *mysql, *connect_res;
	char *query;
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "SELECT msg_enc, msg_sig FROM return_relid WHERE reqid = '" );
	mysql_real_escape_string( mysql, strend(query), reqid, strlen(reqid) );
	strcat( query, "';" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
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
	free( query );
close:
	mysql_close( mysql );
	fflush( stdout );
}

long verify_returned_fr_relid( MYSQL *mysql, unsigned char *fr_relid )
{
	long result = 0;
	char *fr_relid_str = bin2hex( fr_relid, RELID_SIZE );
	int query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	/* Make the query. */
	char *query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "SELECT from_id FROM friend_req WHERE fr_relid = '" );
	mysql_real_escape_string( mysql, strend(query), fr_relid_str, strlen(fr_relid_str) );
	strcat( query, "';" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
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
	free( query );
	fflush(stdout);
	return result;
}

long store_user_friend_req( MYSQL *mysql, const char *user, const char *identity, 
		const char *user_reqid_str, const char *fr_relid_str, const char *relid_str )
{
	long result = 0, query_res;
	char *query;

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*8 );
	strcpy( query, "INSERT INTO user_friend_req VALUES('" );
	mysql_real_escape_string( mysql, strend(query), user, strlen(user) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), identity, strlen(identity) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), user_reqid_str, strlen(user_reqid_str) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), fr_relid_str, strlen(fr_relid_str) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), relid_str, strlen(relid_str) );
	strcat( query, "' );" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
	if ( query_res != 0 ) {
		result = ERR_QUERY_ERROR;
		goto query_fail;
	}

query_fail:
	free( query );
	return result;
}

void friend_final( const char *user, const char *reqid_str, const char *identity, 
		const char *id_host, const char *id_user )
{
	/* a) fetches $URI/request-return/$REQID.asc 
	 * b) decrypts and verifies message, must contain correct $FR-RELID
	 * c) stores request for friendee to accept/deny
	 */

	MYSQL *mysql, *connect_res;
	int verifyres, fetchres, decryptres, storeres;
	RSA *user_priv, *id_pub;
	unsigned char *message;
	unsigned char *encrypted, *signature;
	int enclen;
	unsigned siglen;
	unsigned char message_sha1[SHA_DIGEST_LENGTH];
	unsigned char fr_relid[RELID_SIZE], relid[RELID_SIZE];
	char *fr_relid_str, *relid_str;
	unsigned char user_reqid[REQID_SIZE];
	char *user_reqid_str;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity, id_host, id_user );
	if ( id_pub == 0 ) {
		printf("ERROR fetch_public_key failed\n" );
		goto close;
	}

	RelidEncSig encsig;
	fetchres = fetch_relid_net( encsig, id_host, reqid_str );
	if ( fetchres < 0 ) {
		printf("ERROR fetch_relid failed %d\n", fetchres );
		goto close;
	}
	
	/* Convert the encrypted string to binary. */
	encrypted = (unsigned char*)malloc( strlen(encsig.enc) );
	enclen = hex2bin( encrypted, RSA_size(id_pub), encsig.enc );
	if ( enclen <= 0 ) {
		printf("ERROR converting encsig.enc to binary\n" );
		goto close;
	}

	/* Convert the sig to binary. */
	signature = (unsigned char*)malloc( strlen(encsig.sig) );
	siglen = hex2bin( signature, RSA_size(id_pub), encsig.sig );
	if ( siglen <= 0 ) {
		printf("ERROR converting encsig.sig to binary\n" );
		goto close;
	}

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	/* Decrypt the fr_relid+relid. */
	message = (unsigned char*) malloc( RSA_size( user_priv ) );
	decryptres = RSA_private_decrypt( enclen, encrypted, message, user_priv, RSA_PKCS1_PADDING );
	if ( decryptres != REQID_SIZE*2 ) {
		printf("ERROR failed to decrypt fr_reqid\n" );
		goto close;
	}

	/* Verify the fr_relid+relid. */
	SHA1( message, RELID_SIZE*2, message_sha1 );
	verifyres = RSA_verify( NID_sha1, message_sha1, SHA_DIGEST_LENGTH, signature, siglen, id_pub );
	if ( verifyres != 1 ) {
		printf("ERROR failed to verify message\n" );
		goto close;
	}

	memcpy( fr_relid, message, RELID_SIZE );
	memcpy( relid, message+RELID_SIZE, RELID_SIZE );

	verifyres = verify_returned_fr_relid( mysql, fr_relid );
	if ( verifyres != 1 ) {
		printf("ERROR returned fr_relid does not match the one generated\n" );
		goto close;
	}
		
	fr_relid_str = bin2hex( fr_relid, RELID_SIZE );
	relid_str = bin2hex( relid, RELID_SIZE );

	/* Make a user request id. */
	RAND_bytes( user_reqid, REQID_SIZE );
	user_reqid_str = bin2hex( user_reqid, REQID_SIZE );

	storeres = store_user_friend_req( mysql, user, identity, 
			user_reqid_str, fr_relid_str, relid_str );
	
	/* Return the request id for the requester to use. */
	printf( "OK\r\n" );

	free( fr_relid_str );
	free( relid_str );
close:
	mysql_close( mysql );
	fflush( stdout );
}

long delete_user_friend_req( MYSQL *mysql, const char *user, const char *user_reqid )
{
	long result = 0;
	char *query = (char*)malloc( 1024 + 256*6 );

	/* Insert the friend claim. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "DELETE FROM user_friend_req WHERE user = '" );
	mysql_real_escape_string( mysql, strend(query), user, strlen(user) );
	strcat( query, "' AND user_reqid = '" );
	mysql_real_escape_string( mysql, strend(query), user_reqid, strlen(user_reqid) );
	strcat( query, "';" );

	/* Execute the query. */
	int query_res = mysql_query( mysql, query );
	if ( query_res != 0 )
		result = ERR_QUERY_ERROR;

	free( query );
	return result;
}

void accept_friend( const char *key, const char *user, const char *user_reqid )
{
	MYSQL *mysql, *connect_res;
	char *query;
	long query_res;
	MYSQL_RES *result;
	MYSQL_ROW row;

	/* Check the authentication. */
	if ( strcmp( key, CFG_COMM_KEY ) != 0 ) {
		printf( "ERROR communication key invalid\r\n" );
		goto flush;
	}

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "SELECT from_id, fr_relid, relid FROM user_friend_req WHERE user = '" );
	mysql_real_escape_string( mysql, strend(query), user, strlen(user) );
	strcat( query, "' AND user_reqid = '" );
	mysql_real_escape_string( mysql, strend(query), user_reqid, strlen(user_reqid) );
	strcat( query, "';" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
	if ( query_res != 0 ) {
		printf( "ERROR internal error: %s %d\r\n", __FILE__, __LINE__ );
		goto query_fail;
	}

	/* Check for a result. */
	result = mysql_store_result( mysql );
	row = mysql_fetch_row( result );
	if ( !row ) {
		printf( "ERROR request not found\r\n" );
		goto query_fail;
	}

	/* The friendship has been accepted. Store the claim. The fr_relid is the
	 * one that we made on this end. It becomes the put_relid. */
	store_friend_claim( mysql, user, row[0], row[1], row[2] );

	/* Remove the user friend request. */
	delete_user_friend_req( mysql, user, user_reqid );

	printf( "OK\r\n" );

	mysql_free_result( result );
query_fail:
	free( query );
close:
	mysql_close( mysql );
flush:
	fflush( stdout );
}

long store_flogin_tok( MYSQL *mysql, const char *user, 
		const char *identity, char *flogin_tok_str, char *flogin_reqid_str,
		unsigned char *encrypted, int enclen, unsigned char *signature, int siglen )
{
	long result = 0;

	char *msg_enc = bin2hex( encrypted, enclen );
	char *msg_sig = bin2hex( signature, siglen );
	char *query = (char*)malloc( 1024 + 256*6 );

	/* Make the query. */
	strcpy( query, "INSERT INTO flogin_tok VALUES('" );
	mysql_real_escape_string( mysql, strend(query), user, strlen(user) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), identity, strlen(identity) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), flogin_tok_str, strlen(flogin_tok_str));
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), flogin_reqid_str, strlen(flogin_reqid_str));
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), msg_enc, strlen(msg_enc) );
	strcat( query, "', '" );
	mysql_real_escape_string( mysql, strend(query), msg_sig, strlen(msg_sig) );
	strcat( query, "' );" );

	/* Execute the query. */
	int query_res = mysql_query( mysql, query );
	if ( query_res != 0 )
		result = ERR_QUERY_ERROR;

	free( msg_enc );
	free( msg_sig );
	free( query );

	return result;
}

long check_friend_claim( Identity &identity, MYSQL *mysql, const char *user, const char *friend_hash )
{
	long result = 0;
	char *query;
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "SELECT friend_id FROM friend_claim WHERE user='" );
	mysql_real_escape_string( mysql, strend(query), user, strlen(user) );
	strcat( query, "' AND friend_hash='" );
	mysql_real_escape_string( mysql, strend(query), friend_hash, strlen(friend_hash) );
	strcat( query, "';" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
	if ( query_res != 0 ) {
		result = ERR_QUERY_ERROR;
		goto query_fail;
	}

	select_res = mysql_store_result( mysql );
	row = mysql_fetch_row( select_res );
	if ( row ) {
		identity.identity = strdup( row[0] );
		parse_identity( identity );
		result = 1;
	}

	/* Done. */
	mysql_free_result( select_res );

query_fail:
	free( query );
	return result;
}

void flogin( const char *user, const char *hash )
{
	MYSQL *mysql, *connect_res;
	int sigres;
	RSA *user_priv, *id_pub;

	unsigned char flogin_tok[RELID_SIZE], flogin_reqid[RELID_SIZE];
	char *flogin_tok_str, *flogin_reqid_str;
	unsigned char *encrypted, *signature;
	int enclen;
	unsigned siglen;
	unsigned char relid_sha1[SHA_DIGEST_LENGTH];
	long friend_claim;
	Identity friend_id;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Check if this identity is our friend. */
	friend_claim = check_friend_claim( friend_id, mysql, user, hash );
	if ( friend_claim <= 0 ) {
		/* No friend claim ... send back a reqid anyways. Don't want to give
		 * away that there is no claim. */
		
		RAND_bytes( flogin_reqid, RELID_SIZE );
		flogin_reqid_str = bin2hex( flogin_reqid, RELID_SIZE );
		printf( "OK %s\r\n", flogin_reqid_str );
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, friend_id.identity, 
			friend_id.id_host, friend_id.id_user );
	if ( id_pub == 0 ) {
		printf("ERROR fetch_public_key failed\n" );
		goto close;
	}

	/* Generate the login request id and relationship and request ids. */
	RAND_bytes( flogin_tok, RELID_SIZE );
	RAND_bytes( flogin_reqid, RELID_SIZE );
	
	/* Encrypt it. */
	encrypted = (unsigned char*)malloc( RSA_size(id_pub) );
	enclen = RSA_public_encrypt( RELID_SIZE, flogin_tok, encrypted, 
			id_pub, RSA_PKCS1_PADDING );

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	/* Sign the relationship id. */
	signature = (unsigned char*)malloc( RSA_size(user_priv) );
	SHA1( flogin_tok, RELID_SIZE, relid_sha1 );
	sigres = RSA_sign( NID_sha1, relid_sha1, SHA_DIGEST_LENGTH, signature, &siglen, user_priv );

	/* Store the request. */
	flogin_tok_str = bin2hex( flogin_tok, RELID_SIZE );
	flogin_reqid_str = bin2hex( flogin_reqid, RELID_SIZE );

	store_flogin_tok( mysql, user, friend_id.identity, 
			flogin_tok_str, flogin_reqid_str,
			encrypted, enclen, signature, siglen );
	
	/* Return the request id for the requester to use. */
	printf( "OK %s\r\n", flogin_reqid_str );

	free( flogin_tok_str );
close:
	mysql_close( mysql );
	fflush( stdout );
}

void fetch_ftoken( const char *reqid )
{
	MYSQL *mysql, *connect_res;
	char *query;
	long query_res;
	MYSQL_RES *select_res;
	MYSQL_ROW row;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "SELECT msg_enc, msg_sig FROM flogin_tok WHERE flogin_reqid = '" );
	mysql_real_escape_string( mysql, strend(query), reqid, strlen(reqid) );
	strcat( query, "';" );

	/* Execute the query. */
	query_res = mysql_query( mysql, query );
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
	free( query );
close:
	mysql_close( mysql );
	fflush( stdout );
}

void return_ftoken( const char *user, const char *hash, const char *flogin_reqid_str )
{
	/*
	 * a) checks that $FR-URI is a friend
	 * b) if browser is not logged in fails the process (no redirect).
	 * c) fetches $FR-URI/tokens/$FR-RELID.asc
	 * d) decrypts and verifies the token
	 * e) redirects the browser to $FP-URI/submit-token?uri=$URI&token=$TOK
	 */
	MYSQL *mysql, *connect_res;
	int verifyres, fetchres, decryptres;
	RSA *user_priv, *id_pub;
	unsigned char *flogin_tok;
	unsigned char *encrypted, *signature;
	int enclen;
	unsigned siglen;
	unsigned char ftoken_sha1[SHA_DIGEST_LENGTH];
	char *flogin_tok_str;
	long friend_claim;
	Identity friend_id;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, CFG_DB_HOST, CFG_DB_USER, 
			CFG_ADMIN_PASS, CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Check if this identity is our friend. */
	friend_claim = check_friend_claim( friend_id, mysql, user, hash );
	if ( friend_claim <= 0 ) {
		/* No friend claim ... we can reveal this since return_ftoken requires
		 * that the user be logged in. */
		printf( "ERROR not a friend of mine\r\n" );
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, friend_id.identity, friend_id.id_host, friend_id.id_user );
	if ( id_pub == 0 ) {
		printf("ERROR fetch_public_key failed\n" );
		goto close;
	}

	RelidEncSig encsig;
	fetchres = fetch_ftoken_net( encsig, friend_id.id_host, flogin_reqid_str );
	if ( fetchres < 0 ) {
		printf("ERROR fetch_flogin_relid failed %d\n", fetchres );
		goto close;
	}
	
	/* Convert the encrypted string to binary. */
	encrypted = (unsigned char*)malloc( strlen(encsig.enc) );
	enclen = hex2bin( encrypted, RSA_size(id_pub), encsig.enc );
	if ( enclen <= 0 ) {
		printf("ERROR converting encsig.enc to binary\n" );
		goto close;
	}

	/* Convert the sig to binary. */
	signature = (unsigned char*)malloc( strlen(encsig.sig) );
	siglen = hex2bin( signature, RSA_size(id_pub), encsig.sig );
	if ( siglen <= 0 ) {
		printf("ERROR converting encsig.sig to binary\n" );
		goto close;
	}

	/* Load the private key for the user the request is for. */
	user_priv = load_key( mysql, user );

	/* Decrypt the flogin_tok. */
	flogin_tok = (unsigned char*) malloc( RSA_size( user_priv ) );
	decryptres = RSA_private_decrypt( enclen, encrypted, flogin_tok, user_priv, RSA_PKCS1_PADDING );
	if ( decryptres != REQID_SIZE ) {
		printf("ERROR failed to decrypt flogin_tok\n" );
		goto close;
	}

	/* Verify the flogin_tok. */
	SHA1( flogin_tok, RELID_SIZE, ftoken_sha1 );
	verifyres = RSA_verify( NID_sha1, ftoken_sha1, SHA_DIGEST_LENGTH, signature, siglen, id_pub );
	if ( verifyres != 1 ) {
		printf("ERROR failed to verify flogin_tok\n" );
		goto close;
	}

	flogin_tok_str = bin2hex( flogin_tok, RELID_SIZE );

	/* Return the login token for the requester to use. */
	printf( "OK %s\r\n", flogin_tok_str );

	free( flogin_tok_str );
close:
	mysql_close( mysql );
	fflush( stdout );
}
