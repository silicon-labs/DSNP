/*
 * Copyright (c) 2009-2011, Adrian Thurston <thurston@complang.org>
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
#include "schema.h"

#include <mysql/mysql.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

MYSQL *ConfigCtx::dbConnect( const String &host, const String &database,
		const String &user, const String &pass )
{
	assert( c != 0 );

	/* Open the database connection. */
	MYSQL *mysql = mysql_init(0);
	MYSQL *connect_res = mysql_real_connect( mysql, host, 
		user, pass, database, 0, 0, 0 );
	if ( connect_res == 0 ) {
		error("failed to connect to the database: %s\n", mysql_error(mysql));

		/* LOG THIS */
		mysql_close( mysql );
		mysql = 0;
	}

	return mysql;
}

MYSQL *ConfigCtx::dbConnect()
{
	/* This is used only for the primary database. Good place to check the
	 * schema version. */
	MYSQL *mysql = dbConnect( c->main->CFG_DB_HOST, c->main->CFG_DB_DATABASE, 
			c->main->CFG_DB_USER, c->main->CFG_DB_PASS );

	DbQuery version( mysql, "SELECT version FROM version" );
	if ( version.rows() != 1 )
		throw SchemaVersionMismatch( -1, SCHEMA_VERSION );
	MYSQL_ROW row = version.fetchRow();
	int databaseVersion = atoi( row[0] );
	if ( SCHEMA_VERSION != databaseVersion )
		throw SchemaVersionMismatch( databaseVersion, SCHEMA_VERSION );

	return mysql;
}


long long lastInsertId( MYSQL *mysql )
{
	/* Get the id that was assigned to the message. */
	DbQuery lastInsertId( mysql, "SELECT LAST_INSERT_ID()" );
	return strtoll( lastInsertId.fetchRow()[0], 0, 10 );
}

/*
 * %e escaped string
 */

/* Format and execute a query. */
int execQueryVa( MYSQL *mysql, bool log, const char *fmt, va_list vls )
{
	long len = 0;
	const char *src = fmt;

	/* First calculate the space we need. */
	va_list vl1;
	va_copy( vl1, vls );
	while ( true ) {
		const char *p = strchr( src, '%' );
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
				char *a = va_arg(vl1, char*);
				if ( a == 0 )
					len += 4;
				else
					len += strlen(a) * 2;
				break;
			}
			case 'd': {
				va_arg(vl1, char*);
				long dl = va_arg(vl1, long);
				len += 3 + dl*2;
				break;
			}
			case 'L': {
				va_arg(vl1, long long);
				len += 32;
				break;
			}
			case 'l': {
				va_arg(vl1, long);
				len += 32;
				break;
			}
			case 'b': {
				va_arg(vl1, int);
				len += 8;
				break;
			}
		}
	}
	va_end( vl1 );

	char *query = (char*)malloc( len+1 );
	char *dest = query;
	src = fmt;

	va_list vl2;
	va_copy( vl2, vls );
	while ( true ) {
		const char *p = strchr( src, '%' );
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
				char *a = va_arg(vl2, char*);
				if ( a == 0 ) {
					strcpy( dest, "NULL" );
					dest += 4;
				}
				else {
					*dest++ = '\'';
					dest += mysql_real_escape_string( mysql, dest, a, strlen(a) );
					*dest++ = '\'';
				}
				break;
			}
			case 'd': {
				unsigned char *d = va_arg(vl2, unsigned char*);
				long dl = va_arg(vl2, long);
				char *hex = bin2hex( d, dl );
				dest += sprintf( dest, "x'%s'", hex );
				free( hex );
				break;
			}
			case 'L': {
				long long v = va_arg(vl2, long long);
				dest += sprintf( dest, "%lld", v );
				break;
			}
			case 'l': {
				long v = va_arg(vl2, long);
				dest += sprintf( dest, "%ld", v );
				break;
			}
			case 'b': {
				int b = va_arg(vl2, int);
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
	va_end( vl2 );

	long query_res = mysql_query( mysql, query );

	if ( query_res != 0 )
		throw DbQueryFailed( query, mysql_error(mysql) );
	else if ( log ) {
		/* FIXME: this should use a debugging facility. */
		message("query log: %s\n", query );
	}

	free( query );
	return query_res;
}

int exec_query( MYSQL *mysql, const char *fmt, ... )
{
	va_list args;
	va_start( args, fmt );
	int res = execQueryVa( mysql, false, fmt, args );
	va_end( args );
	return res;
}

DbQuery::DbQuery( MYSQL *mysql, const char *fmt, ... )
:
	mysql(mysql),
	result(0)
{
	va_list args;
	va_start( args, fmt );
	execQueryVa( mysql, false, fmt, args );
	va_end( args );

	result = mysql_store_result( mysql );
}

DbQuery::DbQuery( DbQuery::Log, MYSQL *mysql, const char *fmt, ... )
:
	mysql(mysql),
	result(0)
{
	va_list args;
	va_start( args, fmt );
	execQueryVa( mysql, true, fmt, args );
	va_end( args );

	result = mysql_store_result( mysql );
}

DbQuery::~DbQuery()
{
	free();
}

void DbQuery::free()
{
	if ( result != 0 )
		mysql_free_result( result );
}
