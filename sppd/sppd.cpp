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
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/md5.h>

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

void pass_hash( char *dest, const char *user, const char *pass )
{
	unsigned char pass_bin[16];
	char pass_comb[1024];
	sprintf( pass_comb, "%s:spp:%s", user, pass );
	MD5( (unsigned char*)pass_comb, strlen(pass_comb), pass_bin );
	sprintf( dest, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x", 
		pass_bin[0], pass_bin[1], pass_bin[2], pass_bin[3],
		pass_bin[4], pass_bin[5], pass_bin[6], pass_bin[7],
		pass_bin[8], pass_bin[9], pass_bin[10], pass_bin[11],
		pass_bin[12], pass_bin[13], pass_bin[14], pass_bin[15] );
}

void new_user( const char *key, const char *user, const char *pass, const char *email )
{
	char *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	RSA *rsa;
	MYSQL *mysql, *connect_res;
	char pass_hashed[33];
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
	pass_hash( pass_hashed, user, pass );

	/* Create the query. */
	query = (char*)malloc( 1024 + 256*15 );
	strcpy( query, "insert into user values('" );
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
	strcpy( query, "select rsa_n, rsa_e from user where user = '" );
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
	printf( "OK %s %s\n", row[0], row[1] );

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

void friend_req( const char *user, const char *identity, const char *host )
{
	/* a) verifies challenge response
	 * b) fetches $URI/id.asc (using SSL)
	 * c) randomly generates a one-way relationship id ($FR-RELID)
	 * d) randomly generates a one-way request id ($FR-REQID)
	 * e) encrypts $FR-RELID to friender and signs it
	 * f) makes message available at $FR-URI/friend-request/$FR-REQID.asc
	 * g) redirects the user's browser to $URI/return-relid?uri=$FR-URI&reqid=$FR-REQID
	 */

	PublicKey pub;
	long fr = fetch_public_key( pub, host, user );
	if ( fr < 0 ) {
		printf("fetch failed: %ld\n", fr );
		return;
	}

	printf( "pub: %s %s\n", pub.n, pub.e );
}
