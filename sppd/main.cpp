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


#include <mysql.h>
#include <string.h>

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


int create_user( const char *user, const char *pass, const char *email )
{
	char *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	RSA *rsa;
	MYSQL *mysql, *connect_res;
	char pass_hashed[33];
	char *query;
	int query_res;

	RAND_load_file("/dev/urandom", 1024);
	rsa = RSA_generate_key( 1024, RSA_F4, 0, 0 );

	if ( rsa == 0 ) {
		fprintf( stderr, "error: key generation failed\n");
		return -1;
	}

	n = BN_bn2hex( rsa->n );
	e = BN_bn2hex( rsa->e );
	d = BN_bn2hex( rsa->d );
	p = BN_bn2hex( rsa->p );
	q = BN_bn2hex( rsa->q );
	dmp1 = BN_bn2hex( rsa->dmp1 );
	dmq1 = BN_bn2hex( rsa->dmq1 );
	iqmp = BN_bn2hex( rsa->iqmp );

	printf( "n\n%s\n\n", n );
	printf( "e\n%s\n\n", e );
	printf( "d\n%s\n\n", d );
	printf( "p\n%s\n\n", p );
	printf( "q\n%s\n\n", q );
	printf( "dmp1\n%s\n\n", dmp1 );
	printf( "dmq1\n%s\n\n", dmq1 );
	printf( "iqmp\n%s\n\n", iqmp );

	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, "localhost", "spp", "g7x6dqwer", "spp", 0, 0, 0 );
	if ( connect_res == 0 ) {
		fprintf( stderr, "error: failed to connect to the database\n");
		return -1;
	}

	query = (char*)malloc( 1024 + 256*15 );

	pass_hash( pass_hashed, user, pass );

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

	printf( "query: %s\n", query );

	query_res = mysql_query( mysql, query );
	if ( query_res != 0 ) {
		fprintf( stderr, "error: insert query failed\n");
		return -1;
	}

	free( query );

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

	return 0;
}

int main( int argc, char **argv )
{
	create_user( "Adrian.Thurston", "iduri", "thurston@complang.org" );
}
