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

int main( int argc, char **argv )
{
	if ( argc != 2 ) {
		fprintf( stderr, "expecting one argument: the conf file\n" );
		exit(1);
	}

	read_rcfile( argv[1] );
	parse_loop();
}
