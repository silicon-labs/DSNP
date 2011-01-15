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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "dsnp.h"
#include "error.h"

Config *c = 0, *config_first = 0, *config_last = 0;

const char *cfgVals[] = {
	/* NOTE: must mirror the Config structure. */
	"CFG_URI",
	"CFG_HOST", 
	"CFG_PATH",
	"CFG_DB_HOST",
	"CFG_DB_DATABASE",
	"CFG_DB_USER",
	"CFG_DB_PASS",
	"CFG_COMM_KEY",
	"CFG_PORT",
	"CFG_TLS_CRT",
	"CFG_TLS_KEY",
	"CFG_TLS_CA_CERTS",
};

void processValue( const char *n, long nl, const char *v, long vl )
{
	long numCV = sizeof(cfgVals) / sizeof(const char*);
	for ( long i = 0; i < numCV; i++ ) {
		if ( strncmp( cfgVals[i], n, nl ) == 0 ) {
			char *dest = new char[vl+1];
			memcpy( dest, v, vl );
			dest[vl] = 0;
			((char**)c)[i] = dest;
		}
	}
}

void processSection( const char *n, long nl )
{
	/* Create the config. */
	c = new Config;
	memset( c, 0, sizeof(Config) );

	/* Append the config to the config list. */
	if ( config_first == 0 )
		config_first = config_last = c;
	else {
		config_last->next = c;
		config_last = c;
	}

	/* Copy the name in. */
	c->name = new char[nl+1];
	memcpy( c->name, n, nl );
	c->name[nl] = 0;
}

%%{
	machine rcfile;

	ws = [ \t];
	var = [a-zA-Z_][a-zA-Z_0-9]*;

	# Open and close a variable name.
	action sn { n1 = p; }
	action ln { n2 = p; }

	# Open and close a value.
	action sv { v1 = p; }
	action lv { v2 = p; }

	value = var >sn %ln ws* '=' 
		ws* (^ws [^\n]*)? >sv %lv '\n';

	action value { 
		while ( v2 > v1 && ( v2[-1] == ' ' || v2[-1] == '\t' ) )
			v2--;

		processValue( n1, n2-n1, v1, v2-v1 );
	}

	action section { processSection( n1, n2-n1 ); }

	main := (
		'#' [^\n]* '\n' |
		ws* '\n' |
		value %value |
		'='+ ws* var >sn %ln %section ws* '='+ '\n'
	)*;
}%%

%% write data;

int parseRcFile( const char *data, long length )
{
	long cs;
	const char *p = data, *pe = data + length;
	const char *eof = pe;

	const char *n1, *n2;
	const char *v1, *v2;

	%% write init;
	%% write exec;

	if ( cs < rcfile_first_final )
		fprintf( stderr, "sppd: parse error\n" );
	return 0;
}

void setConfigByUri( const char *uri )
{
	c = config_first;
	while ( c != 0 && strcmp( c->CFG_URI, uri ) != 0 )
		c = c->next;

	if ( c == 0 )
		throw BadSite();
}

void setConfigByName( const char *name )
{
	c = config_first;
	while ( c != 0 && strcmp( c->name, name ) != 0 )
		c = c->next;

	if ( c == 0 )
		throw BadSite();
}
