/*
 * Copyright (c) 2009-2011, Adrian Thurston <thurston@complang.org>
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

void testBase64()
{
	String out;
	String enc;

	out = base64ToBin( "aGVsbG8gdGhlcmUhIQ", 18 );
	printf( "%s\n", out() );

	out = base64ToBin( "YQ", 2);
	printf( "%s\n", out() );

	out = base64ToBin( "YWI", 3);
	printf( "%s\n", out() );

	out = base64ToBin( "YWJj", 4);
	printf( "%s\n", out() );

	out = base64ToBin( "YWJjZA", 6);
	printf( "%s\n", out() );

	out = base64ToBin( "YWJjZGU", 7);
	printf( "%s\n", out() );

	out = base64ToBin( "YWJjZGVm", 8);
	printf( "%s\n", out() );

	out = base64ToBin( "YWJjZGVmZw", 10);
	printf( "%s\n", out() );

	out = base64ToBin( "YWJjZGVmZ2g", 11);
	printf( "%s\n", out() );

	enc = binToBase64( (const u_char*)"a", 1 );
	printf( "%s\n", enc() );

	enc = binToBase64( (const u_char*)"ab", 2 );
	printf( "%s\n", enc() );

	enc = binToBase64( (const u_char*)"abc", 3 );
	printf( "%s\n", enc() );

	enc = binToBase64( (const u_char*)"abcd", 4 );
	printf( "%s\n", enc() );

	enc = binToBase64( (const u_char*)"abcde", 5 );
	printf( "%s\n", enc() );

	enc = binToBase64( (const u_char*)"abcdef", 6 );
	printf( "%s\n", enc() );
}

void test_base64_2()
{
	u_char token[TOKEN_SIZE];
	memset( token, 0, TOKEN_SIZE );
	RAND_bytes( token, TOKEN_SIZE );
	String tokenStr = binToBase64( token, TOKEN_SIZE );
	printf( "%s\n", tokenStr() );
}

#if 0
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

#endif
