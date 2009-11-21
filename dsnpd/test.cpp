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

#include "dsnpd.h"
#include "encrypt.h"
#include "string.h"
#include "disttree.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql.h>
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

	set_config_by_name( "spp" );
	MYSQL *mysql, *connect_res;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );

	if ( connect_res == 0 )
		fatal( "ERROR failed to connect to the database\r\n");

	long socketFd = open_inet_connection( "localhost", 7070 );
	if ( socketFd < 0 )
		fatal("connection\n");

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *bio = BIO_new( BIO_f_buffer() );
	BIO_push( bio, socketBio );

	/* Send the request. */
	BIO_printf( bio,
		"SPP/0.1 https://localhost/spp/\r\n"
		"start_tls\r\n" );
	BIO_flush( bio );

	int len = BIO_gets( bio, buf, 8192 );
	buf[len] = 0;
	message( "result: %s\n", buf );

	sslInitClient();
	bioIn = bioOut = sslStartClient( socketBio, socketBio, "localhost" );

	BIO_printf( bioOut, "public_key age\r\n" );
	BIO_flush( bioOut );
	len = BIO_gets( bioIn, buf, 8192 );
	buf[len] = 0;
	message( "result: %s\n", buf );
}

void test_base64()
{
	unsigned char out[64];
	char *enc;

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "aGVsbG8gdGhlcmUhIQ" );
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YQ");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWI");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJj");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJjZA");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJjZGU");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJjZGVm");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJjZGVmZw");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJjZGVmZ2g");
	printf( "%s\n", out );

	enc = bin_to_base64( (const u_char*) "a", 1 );
	printf( "%s\n", enc );

	enc = bin_to_base64( (const u_char*) "ab", 2 );
	printf( "%s\n", enc );

	enc = bin_to_base64( (const u_char*) "abc", 3 );
	printf( "%s\n", enc );

	enc = bin_to_base64( (const u_char*) "abcd", 4 );
	printf( "%s\n", enc );

	enc = bin_to_base64( (const u_char*) "abcde", 5 );
	printf( "%s\n", enc );

	enc = bin_to_base64( (const u_char*) "abcdef", 6 );
	printf( "%s\n", enc );
}

void test_base64_2()
{
	u_char token[TOKEN_SIZE];
	memset( token, 0, TOKEN_SIZE );
	RAND_bytes( token, TOKEN_SIZE );
	char *token_str = bin_to_base64( token, TOKEN_SIZE );
	printf( "%s\n", token_str );
}

void test_current_put_bk()
{
	set_config_by_name( "spp" );
	MYSQL *mysql, *connect_res;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );

	long long generation;
	String broadcastKey;
	currentPutBk( mysql, "age", generation, broadcastKey );

	printf( "%lld %s\n", generation, broadcastKey.data );
}


void update( MYSQL *mysql )
{
	DbQuery update( mysql,
		"UPDATE get_tree "
		"SET broadcast_key = 'aaa' "
		"WHERE user = 'foo' AND friend_id = 'bar' AND generation = 66" );

	printf( "affected rows: %ld\n", update.affectedRows() );
}

void tree_load()
{
	set_config_by_name( "spp" );
	MYSQL *mysql, *connect_res;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );

	forward_tree_swap( mysql, "age",
		"https://localhost/spp/pat/",
		"https://localhost/spp/sarah/" );
}

void checkTree()
{
	set_config_by_name( "yoho" );
	MYSQL *mysql, *connect_res;

	/* Open the database connection. */
	mysql = mysql_init(0);
	connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	
	checkTree( mysql, "age" );
}

void run_test()
{
	checkTree();
}
