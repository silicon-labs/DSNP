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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "sppd.h"

char *alloc_string( const char *s, const char *e )
{
	long length = e-s;
	char *result = (char*)malloc( length+1 );
	memcpy( result, s, length );
	result[length] = 0;
	return result;
}

%%{
	machine parser;

	comm_key = [a-f0-9]+   >{k1=p;} %{k2=p;};
	user = [a-zA-Z0-9_.]+  >{u1=p;} %{u2=p;};
	pass = graph+          >{p1=p;} %{p2=p;};
	email = graph+         >{e1=p;} %{e2=p;};

	EOL = '\r'? '\n';

	action newuser {
		char *key = alloc_string( k1, k2 );
		char *user = alloc_string( u1, u2 );
		char *pass = alloc_string( p1, p2 );
		char *email = alloc_string( e1, e2 );

		create_user( key, user, pass, email );

		free( key );
		free( user );
		free( pass );
		free( email );
	}

	commands := |* 
		'newuser'i ' ' comm_key ' ' user ' ' pass ' ' email EOL @newuser;
	*|;

	main := 'SPP'i . '/0.1' EOL @{ fgoto commands; };
}%%

%% write data;

int parse_loop()
{
	long cs, act;
	const char *k1, *k2;
	const char *ts, *te;
	const char *u1, *u2;
	const char *p1, *p2;
	const char *e1, *e2;

	%% write init;

	while ( true ) {
		static char buf[1024];
		long len = read( 1, buf, 1024 );

		if ( len < 0 ) {
			fprintf( stderr, "sppd: error reading from socket\n" );
			exit(1);
		}

		const char *p = buf, *pe = buf + len;
		%% write exec;

		if ( cs < parser_first_final ) {
			if ( cs == parser_error )
				fprintf( stderr, "sppd: parse error\n" );
			else
				fprintf( stderr, "sppd: input not complete\n" );
			exit(1);
		}

		if ( len == 0 )
			break;
	}

	return 0;
}
