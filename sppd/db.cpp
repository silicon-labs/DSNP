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
#include <mysql.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

MYSQL *db_connect()
{
	/* Open the database connection. */
	MYSQL *mysql = mysql_init(0);
	MYSQL *connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		error("failed to connect to the database\n");

		/* LOG THIS */
		mysql_close( mysql );
		mysql = 0;
	}

	return mysql;
}

/*
 * %e escaped string
 */

/* Format and execute a query. */
int exec_query( MYSQL *mysql, const char *fmt, ... )
{
	long len = 0;
	va_list vl;
	const char *src = fmt;

	/* First calculate the space we need. */
	va_start(vl, fmt);
	while ( true ) {
		char *p = strchr( src, '%' );
		if ( p == 0 ) {
			/* No more items. Count the rest. */
			len += strlen( src );
			break;
		}

		long seg_len = p-src;

		/* Add two for the single quotes around the item. */
		len += seg_len + 2;

		/* Need to skip over the %s. */
		src += seg_len + 2;

		switch ( p[1] ) {
			case 'e': {
				char *a = va_arg(vl, char*);
				len += strlen(a) * 2;
				break;
			}
			case 'L': {
				va_arg(vl, long long);
				len += 32;
				break;
			}
			case 'l': {
				va_arg(vl, long);
				len += 32;
				break;
			}
			case 'b': {
				va_arg(vl, int);
				len += 8;
				break;
			}
		}
	}
	va_end(vl);

	char *query = (char*)malloc( len+1 );
	char *dest = query;
	src = fmt;

	va_start(vl, fmt);
	while ( true ) {
		char *p = strchr( src, '%' );
		if ( p == 0 ) {
			/* No more items. Copy the rest. */
			strcpy( dest, src );
			break;
		}
		
		long len = p-src;
		memcpy( dest, src, len );
		dest += len;
		src += len + 2;

		switch ( p[1] ) {
			case 'e': {
				*dest++ = '\'';

				char *a = va_arg(vl, char*);
				len = strlen(a);
				len = mysql_real_escape_string( mysql, dest, a, len );
				dest += len;

				*dest++ = '\'';
				break;
			}
			case 'L': {
				long long v = va_arg(vl, long long);
				sprintf( dest, "%lld", v );
				dest += strlen(dest);
				break;
			}
			case 'l': {
				long v = va_arg(vl, long);
				sprintf( dest, "%ld", v );
				dest += strlen(dest);
				break;
			}
			case 'b': {
				int b = va_arg(vl, int);
				if ( b ) {
					strcpy( dest, "TRUE" );
					dest += 4;
				}
				else {
					strcpy( dest, "FALSE" );
					dest += 5;
				}
				break;
			}
		}
	}
	va_end(vl);

	long query_res = mysql_query( mysql, query );

	if ( query_res != 0 ) {
		printf( "ERROR mysql_query failed: %s\r\n", query );
		exit(1);
	}

	free( query );
	return query_res;
}


