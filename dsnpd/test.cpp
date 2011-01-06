/*
 * Copyright (c) 2009, Adrian Thurston <thurston@complang.org>
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

#include <mysql/mysql.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOGIN_TOKEN_LASTS 86400
void test_tls()
{
	static char buf[8192];

	setConfigByName( "spp" );
	MYSQL *mysql, *connect_res;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_DB_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );

	if ( connect_res == 0 )
		fatal( "ERROR failed to connect to the database\r\n");

	long socketFd = openInetConnection( "localhost", 7070 );
	if ( socketFd < 0 )
		fatal("connection\n");

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *bio = BIO_new( BIO_f_buffer() );
	BIO_push( bio, socketBio );

	/* Send the request. */
	BIO_printf( bio,
		"DSNP/0.1 https://localhost/spp/\r\n"
		"start_tls\r\n" );
	(void)BIO_flush( bio );

	int len = BIO_gets( bio, buf, 8192 );
	buf[len] = 0;
	message( "result: %s\n", buf );

	sslInitClient();
	bioIn = bioOut = sslStartClient( socketBio, socketBio, "localhost" );

	BIO_printf( bioOut, "public_key age\r\n" );
	(void)BIO_flush( bioOut );
	len = BIO_gets( bioIn, buf, 8192 );
	buf[len] = 0;
	message( "result: %s\n", buf );
}

void testBase64()
{
	unsigned char out[64];
	char *enc;

	memset( out, 0, 64 );
	base64ToBin( out, "aGVsbG8gdGhlcmUhIQ", 18 );
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64ToBin( out, "YQ", 2);
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64ToBin( out, "YWI", 3);
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64ToBin( out, "YWJj", 4);
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64ToBin( out, "YWJjZA", 6);
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64ToBin( out, "YWJjZGU", 7);
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64ToBin( out, "YWJjZGVm", 8);
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64ToBin( out, "YWJjZGVmZw", 10);
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64ToBin( out, "YWJjZGVmZ2g", 11);
	printf( "%s\n", out );

	enc = binToBase64( (const u_char*) "a", 1 );
	printf( "%s\n", enc );

	enc = binToBase64( (const u_char*) "ab", 2 );
	printf( "%s\n", enc );

	enc = binToBase64( (const u_char*) "abc", 3 );
	printf( "%s\n", enc );

	enc = binToBase64( (const u_char*) "abcd", 4 );
	printf( "%s\n", enc );

	enc = binToBase64( (const u_char*) "abcde", 5 );
	printf( "%s\n", enc );

	enc = binToBase64( (const u_char*) "abcdef", 6 );
	printf( "%s\n", enc );
}

void test_base64_2()
{
	u_char token[TOKEN_SIZE];
	memset( token, 0, TOKEN_SIZE );
	RAND_bytes( token, TOKEN_SIZE );
	char *token_str = binToBase64( token, TOKEN_SIZE );
	printf( "%s\n", token_str );
}

void test_current_put_bk()
{
	setConfigByName( "spp" );
	MYSQL *mysql, *connect_res;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_DB_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );

	//currentPutBk( mysql, "age", generation, broadcastKey );
	//printf( "%lld %s\n", generation, broadcastKey.data );
}

void tree_load()
{
	setConfigByName( "spp" );
	MYSQL *mysql, *connect_res;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_DB_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
}

void friendProof()
{
	setConfigByName( "yoho" );
	MYSQL *mysql, *connect_res;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_DB_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
}

void testString()
{
	String string;
	string = "foo";
	message("foo%s\n", string() );
}

void runTest()
{
	testString();
}
