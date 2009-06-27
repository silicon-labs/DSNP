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

#include <openssl/rand.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "sppd.h"

BIO *bioIn = 0;
BIO *bioOut = 0;

void read_rcfile( const char *confFile )
{
	FILE *rcfile = fopen( confFile, "r" );
	if ( rcfile == NULL ) {
		fprintf( stderr, "failed to open the config file \"%s\", exiting\n", confFile );
		exit(1);
	}

	/* FIXME: this must be fixed. */
	static char buf[1024*16];
	long len = fread( buf, 1, 1024*16, rcfile );
	rcfile_parse( buf, len );
}

const char *configFile = 0;
const char *siteName = 0;
bool runQueue = false;
bool test = false;

int check_args( int argc, char **argv )
{
	while ( true ) {
		int opt = getopt( argc, argv, "q:t" );

		if ( opt < 0 )
			break;

		switch ( opt ) {
			case 'q':
				runQueue = true;
				siteName = optarg;
				break;
			case 't':
				test = true;
				break;
		}
	}

	if ( optind < argc )
		configFile = argv[optind];
	else {
		fprintf( stderr, "expected config file argument\n" );
		exit(1);
	}

	return 0;
}


void start_tls()
{
	BIO_printf( bioOut, "OK\r\n" );
	BIO_flush( bioOut );

	/* Don't need the buffering wrappers anymore. */
	bioIn = BIO_pop( bioIn );
	bioOut = BIO_pop( bioOut );

	sslInitServer();
	bioIn = bioOut = sslStartServer( bioIn, bioOut );
}

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
	base64_to_bin( out, 64, "aGVsbG8gdGhlcmUhIQ==" );
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YQ==");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWI=");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJj");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJjZA==");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJjZGU=");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJjZGVm");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJjZGVmZw==");
	printf( "%s\n", out );

	memset( out, 0, 64 );
	base64_to_bin( out, 64, "YWJjZGVmZ2g=");
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

void run_test()
{
	test_base64();
}

void dieHandler( int signum )
{
	error( "caught signal %d, exiting\n", signum );
	exit(1);
}

void setupSignals()
{
	signal( SIGHUP, &dieHandler );
	signal( SIGINT, &dieHandler );
	signal( SIGQUIT, &dieHandler );
	signal( SIGILL, &dieHandler );
	signal( SIGABRT, &dieHandler );
	signal( SIGFPE, &dieHandler );
	signal( SIGSEGV, &dieHandler );
	signal( SIGPIPE, &dieHandler );
	signal( SIGTERM, &dieHandler );
}

int sslTest();

int main( int argc, char **argv )
{
	if ( check_args( argc, argv ) < 0 ) {
		fprintf( stderr, "expecting: sppd [options] config\n" );
		fprintf( stderr, "  options: -q<site>    don't listen, run queue\n" );
		exit(1);
	}

	/* Set up the input BIO to wrap stdin. */
	BIO *bioFdIn = BIO_new_fd( fileno(stdin), BIO_NOCLOSE );
	bioIn = BIO_new( BIO_f_buffer() );
	BIO_push( bioIn, bioFdIn );

	/* Set up the output bio to wrap stdout. */
	BIO *bioFdOut = BIO_new_fd( fileno(stdout), BIO_NOCLOSE );
	bioOut = BIO_new( BIO_f_buffer() );
	BIO_push( bioOut, bioFdOut );

	setupSignals();

	read_rcfile( configFile );

	RAND_load_file("/dev/urandom", 1024);

	openLogFile();

	if ( runQueue )
		run_queue( siteName );
	else if ( test )
		run_test();
	else 
		server_parse_loop();
}
