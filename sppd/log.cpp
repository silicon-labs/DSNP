/*
 * Copyright (c) 2009, Adrian Thurston <thurston@complang.org>
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

#include "sppd.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#define FATAL_EXIT_CODE 1
#define LOG_FILE "/tmp/sppd.log"
FILE *logFile;

void openLogFile()
{
	if ( logFile == 0 ) {
		mode_t oldMode = umask( 0000 );
		logFile = fopen( LOG_FILE, "at" );
		umask( oldMode );
		if ( logFile == 0 ) {
			fprintf( stderr, "could not open logfile %s\n", LOG_FILE );
			exit(FATAL_EXIT_CODE);
		}
	}
}

void error( const char *fmt, ... )
{
	va_list args;
	struct tm localTm;
	char timeStr[64];

	time_t t = time(0);
	localtime_r( &t, &localTm );
	strftime( timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTm );

	if ( logFile != 0 ) {
		va_start( args, fmt );
		fprintf( logFile, "ERROR %s: ", timeStr );
		vfprintf( logFile, fmt, args );
		va_end( args );
	}
}

void warning( const char *fmt, ... )
{
	va_list args;
	struct tm localTm;
	char timeStr[64];

	time_t t = time(0);
	localtime_r( &t, &localTm );
	strftime( timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTm );

	if ( logFile != 0 ) {
		va_start( args, fmt );
		fprintf( logFile, "WARNING %s: ", timeStr );
		vfprintf( logFile, fmt, args );
		va_end( args );
	}
}

void message( const char *fmt, ... )
{
	va_list args;
	struct tm localTm;
	char timeStr[64];

	time_t t = time(0);
	localtime_r( &t, &localTm );
	strftime( timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTm );

	if ( logFile != 0 ) {
		va_start( args, fmt );
		fprintf( logFile, "msg %s: ", timeStr );
		vfprintf( logFile, fmt, args );
		va_end( args );
	}
}

void fatal( const char *fmt, ... )
{
	va_list args;
	struct tm localTm;
	char timeStr[64];

	time_t t = time(0);
	localtime_r( &t, &localTm );
	strftime( timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTm );

	if ( logFile != 0 ) {
		va_start( args, fmt );
		fprintf( logFile, "FATAL %s: ", timeStr );
		vfprintf( logFile, fmt, args );
		va_end( args );
	}
	exit(1);
}

