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
#include "error.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define CFG_READ_LEN 1024

ConfigParser::ConfigParser( const char *confFile, ConfigSlice requestedSlice, Config *config )
:
	config(config),
	curSect(0),
	nextConfigSectionId(0),
	requestedSlice(requestedSlice)
{
	/* Now there is only one config. */
	curSect = new ConfigSection( 0 );

	debug( DBG_CFG, "CFG: main section\n" );

	config->main = curSect;

	FILE *rcfile = fopen( confFile, "r" );
	if ( rcfile == 0 ) 
		fatal( "could not open conf file %s\n", confFile );
	
	init();

	/* Read and parse. */
	char *buf = new char[CFG_READ_LEN];
	while ( true ) {
		long len = fread( buf, 1, CFG_READ_LEN, rcfile );

		if ( len > 0 )
			parseData( buf, len );
		
		if ( len < CFG_READ_LEN )
			break;
	}

	/* Cause EOF. */
	parseData( 0, 0 );

	fclose( rcfile );
	delete[] buf;
}

/* NOTE: The indicies into this array must match the switch in the setValue
 * function. */
ConfigVar ConfigParser::varNames[] = {
	{ "CFG_PORT",             SliceDaemon },
	{ "CFG_DB_HOST",          SliceDaemon },
	{ "CFG_DB_USER",          SliceDaemon },
	{ "CFG_DB_DATABASE",      SliceDaemon },
	{ "CFG_DB_PASS",          SliceDaemon },
	{ "CFG_KEYS_HOST",        SliceKeyAgent },
	{ "CFG_KEYS_USER",        SliceKeyAgent },
	{ "CFG_KEYS_DATABASE",    SliceKeyAgent },
	{ "CFG_KEYS_PASS",        SliceKeyAgent },
	{ "CFG_NOTIF_HOST",       SliceNotifAgent },
	{ "CFG_NOTIF_KEYS_USER",  SliceNotifAgent },
	{ "CFG_NOTIF_DATABASE",   SliceNotifAgent },
	{ "CFG_NOTIF_PASS",       SliceNotifAgent },
	{ "CFG_HOST",             SliceDaemon },
	{ "CFG_TLS_CRT",          SliceDaemon },
	{ "CFG_TLS_KEY",          SliceDaemon },
	{ "CFG_NOTIFICATION",     SliceNotifAgent },
	{ "CFG_COMM_KEY",         SliceDaemon },
	{ "CFG_COMM_KEY",         SliceNotifAgent }
};


void ConfigParser::setValue( int i, const String &value )
{
	switch ( i ) {
		case 0:  curSect->CFG_PORT = value; break;
		case 1:  curSect->CFG_DB_HOST = value; break;
		case 2:  curSect->CFG_DB_USER = value; break;
		case 3:  curSect->CFG_DB_DATABASE = value; break;
		case 4:  curSect->CFG_DB_PASS = value; break;
		case 5:  curSect->CFG_KEYS_HOST = value; break;
		case 6:  curSect->CFG_KEYS_USER = value; break;
		case 7:  curSect->CFG_KEYS_DATABASE = value; break;
		case 8:  curSect->CFG_KEYS_PASS = value; break;
		case 9:  curSect->CFG_NOTIF_HOST = value; break;
		case 10: curSect->CFG_NOTIF_KEYS_USER = value; break;
		case 11: curSect->CFG_NOTIF_DATABASE = value; break;
		case 12: curSect->CFG_NOTIF_PASS = value; break;
		case 13: curSect->CFG_HOST = value; break;
		case 14: curSect->CFG_TLS_CRT = value; break;
		case 15: curSect->CFG_TLS_KEY = value; break;
		case 16: curSect->CFG_NOTIFICATION = value; break;
		/* Appears twice, because we need it in two slices. */
		case 17: curSect->CFG_COMM_KEY = value; break;
		case 18: curSect->CFG_COMM_KEY = value; break;
	}
}

void ConfigParser::processValue()
{
	long numCV = sizeof(varNames) / sizeof(ConfigVar);
	for ( long i = 0; i < numCV; i++ ) {
		/* The var name must be fore all slices, or the slice must match the
		 * slice requested during parsing. */
		if ( requestedSlice == varNames[i].slice ) {
			/* Check for name match. */
			if ( strcmp( varNames[i].name, name() ) == 0 ) {
				setValue( i, value );
				debug( DBG_CFG, "CFG: %s = %s\n", varNames[i].name, value() );
			}
		}
	}
}

void ConfigParser::startHost()
{
	/* Create the config. */
	curSect = new ConfigSection( config->hostList.length() );

	/* n can point to either either 'host' or 'site'. */
	debug( DBG_CFG, "CFG: starting a host section\n" );
	config->hostList.append( curSect );
}

void ConfigParser::startSite()
{
	/* Create the config. */
	curSect = new ConfigSection( config->siteList.length() );
	curSect->name = buf;

	/* n can point to either either 'host' or 'site'. */
	debug( DBG_CFG, "CFG: starting a site section\n" );
	config->siteList.append( curSect );
}

%%{
	machine rcfile;

	ws = [ \t];
	var = [a-zA-Z_][a-zA-Z_0-9]*;

	action clear { buf.clear(); }
	action buf { buf.append(fc); }

	action name  { name.set(buf); }
	action value {
		value.set(buf);
		if ( curSect == 0 )
			throw ConfigParseError();
		processValue();
	}

	value = var >clear $buf %name ws* '=' 
		ws* (^ws [^\n]*)? >clear $buf %value '\n';

	action host {
		startHost();
	}

	host = ( '='+ ws* 'host' ws* '='+ '\n' ) @host;

	action site {
		startSite();
	}

	siteName = var >clear $buf;
	site = ( '='+ ws* 'site' ws+ siteName ws* '='+ '\n' ) @site;

	main := (
		'#' [^\n]* '\n' |
		ws* '\n' |
		value |
		host |
		site
	)*;
}%%

%% write data;

void ConfigParser::init()
{
	%% write init;
}

/* Call with data = 0 && length = 0 to indicate end of file. */
void ConfigParser::parseData( const char *data, long length )
{
	const char *p = data, *pe = data + length;
	//const char *eof = data == 0 ? pe : 0;

	%% write exec;

	if ( cs == rcfile_error )
		throw ConfigParseError();
}
