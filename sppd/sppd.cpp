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
#include <stdarg.h>

/*
 * %e escaped string
 */

/* Format and execute a query. */
int exec_query( MYSQL *mysql, const char *fmt, ... )
{
	long len = 0;
	va_list vl;
	const char *src = fmt;

	/* First calculate the space we need. */
	va_start(vl, fmt);
	while ( true ) {
		char *p = strchr( src, '%' );
		if ( p == 0 ) {
			/* No more items. Count the rest. */
			len += strlen( src );
			break;
		}

		long seg_len = p-src;

		/* Add two for the single quotes around the item. */
		len += seg_len + 2;

		/* Need to skip over the %s. */
		src += seg_len + 2;

		switch ( p[1] ) {
			case 'e': {
				char *a = va_arg(vl, char*);
				len += strlen(a) * 2;
				break;
			}
			case 'L': {
				va_arg(vl, long long);
				len += 32;
				break;
			}
			case 'b': {
				va_arg(vl, int);
				len += 8;
				break;
			}
		}
	}
	va_end(vl);

	char *query = (char*)malloc( len+1 );
	char *dest = query;
	src = fmt;

	va_start(vl, fmt);
	while ( true ) {
		char *p = strchr( src, '%' );
		if ( p == 0 ) {
			/* No more items. Copy the rest. */
			strcpy( dest, src );
			break;
		}
		
		long len = p-src;
		memcpy( dest, src, len );
		dest += len;
		src += len + 2;

		switch ( p[1] ) {
			case 'e': {
				*dest++ = '\'';

				char *a = va_arg(vl, char*);
				len = strlen(a);
				len = mysql_real_escape_string( mysql, dest, a, len );
				dest += len;

				*dest++ = '\'';
				break;
			}
			case 'L': {
				long long v = va_arg(vl, long long);
				sprintf( dest, "%lld", v );
				dest += strlen(dest);
				break;
			}
			case 'b': {
				int b = va_arg(vl, int);
				if ( b ) {
					strcpy( dest, "TRUE" );
					dest += 4;
				}
				else {
					strcpy( dest, "FALSE" );
					dest += 5;
				}
				break;
			}
		}
	}
	va_end(vl);

	long query_res = mysql_query( mysql, query );

	if ( query_res != 0 ) {
		printf( "ERROR mysql_query failed: %s\r\n", query );
		exit(1);
	}

	free( query );
	return query_res;
}

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

void new_user( const char *user, const char *pass, const char *email )
{
	char *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	RSA *rsa;
	MYSQL *mysql, *connect_res;
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

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Hash the password. */
	pass_hashed = pass_hash( user, pass );

	/* Execute the insert. */
	exec_query( mysql, "INSERT INTO user VALUES("
		"%e, %e, %e, %e, %e, %e, %e, %e, %e, %e, %e);", 
		user, pass_hashed, email, n, e, d, p, q, dmp1, dmq1, iqmp );
	
	/* Make the first session key for the user. */
	new_session_key( mysql, user );

	printf( "OK\r\n" );

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
	MYSQL_RES *result;
	MYSQL_ROW row;

	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

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

long store_friend_request( MYSQL *mysql, const char *identity, char *fr_relid_str, 
		char *fr_reqid_str, unsigned char *encrypted, int enclen, 
		unsigned char *signature, int siglen )
{
	long result = 0;

	char *msg_enc = bin2hex( encrypted, enclen );
	char *msg_sig = bin2hex( signature, siglen );
	char *query = (char*)malloc( 1024 + 256*6 );

	/* Make the query. */
	strcpy( query, "INSERT INTO friend_request VALUES('" );
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

void friend_request( const char *user, const char *identity )
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
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity );
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

	store_friend_request( mysql, identity, fr_relid_str, fr_reqid_str, 
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
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "SELECT msg_enc, msg_sig FROM friend_request WHERE fr_reqid = '" );
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
	char *site;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity );
	if ( id_pub == 0 ) {
		printf("ERROR fetch_public_key failed\n" );
		goto close;
	}

	site = get_site( identity );

	RelidEncSig encsig;
	fetchres = fetch_fr_relid_net( encsig, site, id_host, fr_reqid_str );
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
	store_friend_claim( mysql, user, identity, relid_str, fr_relid_str, false );
	
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
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
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
	strcpy( query, "SELECT from_id FROM friend_request WHERE fr_relid = '" );
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

long store_user_friend_request( MYSQL *mysql, const char *user, const char *identity, 
		const char *user_reqid_str, const char *fr_relid_str, const char *relid_str )
{
	long result = 0, query_res;
	char *query;

	/* Make the query. */
	query = (char*)malloc( 1024 + 256*8 );
	strcpy( query, "INSERT INTO user_friend_request VALUES('" );
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
	char *site;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Get the public key for the identity. */
	id_pub = fetch_public_key( mysql, identity );
	if ( id_pub == 0 ) {
		printf("ERROR fetch_public_key failed\n" );
		goto close;
	}

	site = get_site( identity );

	RelidEncSig encsig;
	fetchres = fetch_relid_net( encsig, site, id_host, reqid_str );
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

	storeres = store_user_friend_request( mysql, user, identity, 
			user_reqid_str, fr_relid_str, relid_str );
	
	/* Return the request id for the requester to use. */
	printf( "OK\r\n" );

	free( fr_relid_str );
	free( relid_str );
close:
	mysql_close( mysql );
	fflush( stdout );
}

long delete_user_friend_request( MYSQL *mysql, const char *user, const char *user_reqid )
{
	/* Insert the friend claim. */
	exec_query( mysql, 
		"DELETE FROM user_friend_request WHERE user = %e AND user_reqid = %e;",
		user, user_reqid );

	return 0;
}

long queue_message( MYSQL *mysql, const char *user, const char *to_id, const char *message )
{
	/* Table lock. */
	exec_query( mysql, "LOCK TABLES msg_queue WRITE;");

	/* Queue the message. */
	exec_query( mysql, 
		"INSERT INTO msg_queue VALUES ( %e, %e, %e );",
		user, to_id, message 
	);

	/* Lock releast. */
	exec_query( mysql, "UNLOCK TABLES;");

	return 0;
}

long run_queue_db( MYSQL *mysql )
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
		exec_query( mysql, "LOCK TABLES msg_queue WRITE;");

		mysql_data_seek( select_res, 0 );
		for ( int i = 0; i < rows; i++ ) {
			row = mysql_fetch_row( select_res );

			if ( !sent[i] ) {
				printf("Putting back to the queue: %s %s %s\n", row[0], row[1], row[2] );
				/* Queue the message. */
				exec_query( mysql, 
					"INSERT INTO msg_queue VALUES ( %e, %e, %e );",
					row[0], row[1], row[2] 
				);
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

	run_queue_db( mysql );

close:
	mysql_close( mysql );
	fflush( stdout );
}

int send_current_session_key( MYSQL *mysql, const char *user, const char *identity )
{
	char sk[SK_SIZE_HEX];
	Encrypt encrypt;
	long long generation;
	int sk_result;

	/* Get the latest put session key. */
	sk_result = current_put_sk( mysql, user, sk, &generation );
	if ( sk_result != 1 ) {
		printf( "ERROR fetching session key\r\n");
	}

	int send_res = send_session_key( user, identity, sk, generation );
	if ( send_res < 0 ) {
		fprintf(stderr, "sending failed %d\n", send_res );
	}

	return 0;
}

void accept_friend( const char *user, const char *user_reqid )
{
	MYSQL *mysql, *connect_res;
	MYSQL_RES *result;
	MYSQL_ROW row;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

	/* Execute the query. */
	exec_query( mysql, "SELECT from_id, fr_relid, relid "
		"FROM user_friend_request "
		"WHERE user = %e AND user_reqid = %e;",
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
	delete_user_friend_request( mysql, user, user_reqid );

	send_current_session_key( mysql, user, row[0] );
	forward_tree_insert( mysql, user, row[0], row[1] );

	printf( "OK\r\n" );

	mysql_free_result( result );
close:
	mysql_close( mysql );
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

long check_friend_claim( Identity &identity, MYSQL *mysql, const char *user, 
		const char *friend_hash )
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
		identity.parse();
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
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
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
	id_pub = fetch_public_key( mysql, friend_id.identity );
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
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
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
	char *site;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
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
	id_pub = fetch_public_key( mysql, friend_id.identity );
	if ( id_pub == 0 ) {
		printf("ERROR fetch_public_key failed\n" );
		goto close;
	}

	site = get_site( friend_id.identity );

	RelidEncSig encsig;
	fetchres = fetch_ftoken_net( encsig, site, friend_id.host, flogin_reqid_str );
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

long queue_broadcast( MYSQL *mysql, const char *to_site, const char *relid,
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
		printf("ERROR bad user\r\n");
		goto close;
	}
	friend_id = row[0];
	put_relid = row[1];

	/* Do the encryption. */
	user_priv = load_key( mysql, user );
	encrypt.load( 0, user_priv );
	encrypt.skEncryptSign( session_key, (u_char*)message, strlen(message)+1 );

	/* Find the root user to send to. */
	id.load( friend_id );
	id.parse();

	queue_broadcast( mysql, id.site, put_relid, encrypt.sig,
			strtoll(generation, 0, 10), encrypt.sym );
close:
	return 0;
}

void receive_broadcast( const char *relid, const char *sig,
		long long key_generation, const char *message )
{
	MYSQL *mysql, *connect_res;
	MYSQL_RES *result;
	MYSQL_ROW row;
	char *user, *friend_id, *session_key;
	char *get_fwd_site1, *get_fwd_relid1;
	char *get_fwd_site2, *get_fwd_relid2;
	RSA *id_pub;
	Encrypt encrypt;
	int decryptRes;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

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

	/* Save the message. */
	exec_query( mysql, 
		"INSERT INTO received ( get_relid, message ) "
		"VALUES ( %e, %e )",
		relid, encrypt.decrypted );
	
	/* 
	 * Now do the forwarding.
	 */

	if ( get_fwd_site1 != 0 ) {
		queue_broadcast( mysql, get_fwd_site1, get_fwd_relid1, sig, 
				key_generation, message );
	}

	if ( get_fwd_site2 != 0 ) {
		queue_broadcast( mysql, get_fwd_site2, get_fwd_relid2, sig,
				key_generation, message );
	}

	mysql_free_result( result );

	printf("OK\n");

close:
	mysql_close( mysql );
	fflush(stdout);
}

long send_message( const char *from_user, const char *to_identity, const char *message )
{
	MYSQL *mysql, *connect_res;
	MYSQL_RES *result;
	MYSQL_ROW row;
	RSA *id_pub, *user_priv;
	Encrypt encrypt;
	int encrypt_res;
	const char *relid;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

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

	send_message_net( relid, to_identity, encrypt.enc, encrypt.sig, encrypt.sym );
	
free_result:
	mysql_free_result( result );
close:
	mysql_close( mysql );
	return 0;
}

long send_session_key( const char *from_user, const char *to_identity, 
		const char *session_key, long long generation )
{
	static char buf[8192];

	sprintf( buf,
		"session_key %s %lld\r\n", 
		session_key, generation );

	return send_message( from_user, to_identity, buf );
}

long send_forward_to( const char *from_user, const char *to_identity, 
		int childNum, const char *forwardToSite, const char *relid )
{
	static char buf[8192];

	sprintf( buf, 
		"forward_to %d %s %s\r\n", 
		childNum, forwardToSite, relid );

	return send_message( from_user, to_identity, buf );
}

void receive_message( const char *relid, const char *enc,
		const char *sig, const char *message )
{
	MYSQL *mysql, *connect_res;
	MYSQL_RES *result;
	MYSQL_ROW row;
	RSA *id_pub, *user_priv;
	Encrypt encrypt;
	int decrypt_res;
	const char *user, *friend_id;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
		goto close;
	}

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
close:
	mysql_close( mysql );
	fflush( stdout );
	return;
}

