/*
 * Copyright (c) 2008-2011, Adrian Thurston <thurston@complang.org>
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
#include "string.h"
#include "error.h"
#include "encrypt.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_MSG_LEN 16384

#include <unistd.h>
#include <fcntl.h>

/*
 * Server Loop
 */


%%{
	machine command_parser;

	include common "common.rl";

	main := (
		# Admin commands.
		'new-user' 0 user 0 private_name 0 pass 0
			0 @{
				message( "command: new_user %s %s %s\n", user(), privateName(), pass() );
				server->newUser( user, privateName, pass );
			}
	)*;
}%%

%% write data;

CommandParser::CommandParser( Server *server )
:
	retVal(0),
	mysql(0),
	tls(false),
	exit(false),
	versions(0),
	server(server)
{

	%% write init;
}

Parser::Control CommandParser::data( const char *data, int dlen )
{
	const unsigned char *p = (u_char*)data;
	const unsigned char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( exit && cs >= %%{ write first_final; }%% )
		return Stop;

	/* Did parsing succeed? */
	if ( cs == %%{ write error; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}


