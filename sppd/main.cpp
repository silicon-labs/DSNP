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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sppd.h"

void read_rcfile( const char *confFile )
{
	FILE *rcfile = fopen( confFile, "r" );
	if ( rcfile == NULL ) {
		fprintf( stderr, "failed to open the config file \"%s\", exiting\n", confFile );
		exit(1);
	}

	static char buf[1024];
	long len = fread( buf, 1, 1024, rcfile );
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

void test_function()
{
	set_config_by_name( "spp" );

	/* Open the database connection. */
	MYSQL *mysql = mysql_init(0);
	MYSQL *connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );

	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
	}

	int result = send_message2( "age", "http://localhost/spp/pat/", "foobar" );
	if ( result < 0 ) {
		printf("send_message failed with %d\n", result );
	}
}

int main( int argc, char **argv )
{
	if ( check_args( argc, argv ) < 0 ) {
		fprintf( stderr, "expecting: sppd [options] config\n" );
		fprintf( stderr, "  options: -q<site>    don't listen, run queue\n" );
		exit(1);
	}

	read_rcfile( configFile );

	RAND_load_file("/dev/urandom", 1024);

	if ( runQueue )
		run_queue( siteName );
	else if ( test )
		test_function();
	else 
		server_parse_loop();
}
