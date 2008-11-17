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

	user = [a-zA-Z0-9_.]+  >{u1=p;} %{u2=p;};
	pass = graph+          >{p1=p;} %{p2=p;};
	email = graph+         >{e1=p;} %{e2=p;};

	action newuser {
		char *user = alloc_string( u1, u2 );
		char *pass = alloc_string( p1, p2 );
		char *email = alloc_string( e1, e2 );

		create_user( user, pass, email );

		free( user );
		free( pass );
		free( email );
	}

	commands := |* 
		'login'i '\n';
		'newuser'i ' ' user ' ' pass ' ' email '\n' @newuser;
	*|;

	main := 'SPP'i . '/0.1\n' @{ fgoto commands; };
}%%

%% write data;


int parse( const char *data, long length )
{
	long cs, act;
	const char *p = data, *pe = data + length;

	const char *ts, *te;
	const char *u1, *u2;
	const char *p1, *p2;
	const char *e1, *e2;

	%% write init;
	%% write exec;

	if ( cs < parser_first_final )
		fprintf( stderr, "sppd: parse error\n" );
	return 0;
}
