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

	path_part = (graph-'/')+;

	identity = 
		( 'http://' path_part >{h1=p;} %{h2=p;} '/' ( path_part '/' )* )
		>{i1=p;} %{i2=p;};

	EOL = '\r'? '\n';

	action new_user {
		char *key = alloc_string( k1, k2 );
		char *user = alloc_string( u1, u2 );
		char *pass = alloc_string( p1, p2 );
		char *email = alloc_string( e1, e2 );

		new_user( key, user, pass, email );

		free( key );
		free( user );
		free( pass );
		free( email );
	}

	action public_key {
		char *user = alloc_string( u1, u2 );

		public_key( user );

		free( user );
	}

	action friend_req {
		char *user = alloc_string( u1, u2 );
		char *identity = alloc_string( i1, i2 );
		char *host = alloc_string( h1, h2 );

		friend_req( user, identity, host );

		free( user );
		free( identity );
	}

	commands := |* 
		'public_key'i ' ' user EOL @public_key;
		'friend_req'i ' ' user ' ' identity EOL @friend_req;

		'new_user'i ' ' comm_key ' ' user ' ' pass ' ' email EOL @new_user;
	*|;

	main := 'SPP/0.1'i EOL @{ fgoto commands; };
}%%

%% write data;

const long linelen = 1024;

int server_parse_loop()
{
	long cs, act;
	const char *k1, *k2;
	const char *ts, *te;
	const char *u1, *u2;
	const char *p1, *p2;
	const char *e1, *e2;
	const char *i1, *i2;
	const char *h1, *h2;

	%% write init;

	while ( true ) {
		static char buf[linelen];
		char *result = fgets( buf, linelen, stdin );

		/* Just break when client closes the connection. */
		if ( feof( stdin ) )
			break;

		/* Check for an error in the fgets. */
		if ( ! result )
			return -1;

		/* Did we get a full line? */
		long length = strlen( buf );
		if ( buf[length-1] != '\n' )
			return ERR_LINE_TOO_LONG;

		const char *p = buf, *pe = buf + length;

		%% write exec;

		if ( cs < parser_first_final ) {
			if ( cs == parser_error )
				return ERR_PARSE_ERROR;
			else
				return ERR_UNEXPECTED_END;
		}
	}

	return 0;
}

%%{
	machine public_key;
	write data;
}%%


long fetch_public_key( PublicKey &pub, const char *host, const char *user )
{
	static char buf[1024];
	long result = 0, cs;
	const char *p, *pe;
	const char *n1, *n2, *e1, *e2;
	bool OK = false;

	long socketFd = open_inet_connection( host, atoi(CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	/* Send the request. */
	FILE *writeSocket = fdopen( socketFd, "w" );
	fprintf( writeSocket, "SPP/0.1\r\npublic_key %s\r\n", user );
	fflush( writeSocket );

	/* Read the result. */
	FILE *readSocket = fdopen( socketFd, "r" );
	char *readRes = fgets( buf, 1024, readSocket );

	/* If there was an error then fail the fetch. */
	if ( !readRes ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		EOL = '\r'? '\n';

		n = [0-9A-F]+  >{n1 = p;} %{n2 = p;};
		e = [01]+      >{e1 = p;} %{e2 = p;};

		main := 
			'OK ' n ' ' e EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < public_key_first_final ) {
		result = ERR_PARSE_ERROR;
		goto fail;
	}
	
	if ( !OK ) {
		result = ERR_SERVER_ERROR;
		goto fail;
	}
	
	pub.n = (char*)malloc( n2-n1+1 );
	pub.e = (char*)malloc( e2-e1+1 );
	memcpy( pub.n, n1, n2-n1 );
	memcpy( pub.e, e1, e2-e1 );
	pub.n[n2-n1] = 0;
	pub.e[e2-e1] = 0;

fail:
	fclose( writeSocket );
	fclose( readSocket );
	::close( socketFd );
	return result;
}
