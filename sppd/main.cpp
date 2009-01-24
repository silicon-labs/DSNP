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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
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

int check_args( int argc, char **argv )
{
	if ( argc == 2 )
		configFile = argv[1];
	else if ( argc == 3 ) {
		if ( ! ( argv[1][0] == '-' && argv[1][1] == 'q' ) )
			return -1;
		runQueue = true;
		siteName = argv[1] + 2;
		configFile = argv[2];
	}
	else {
		/* Wrong number of args. */
		return -1;
	}

	return 0;
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
	else 
		server_parse_loop();
}
