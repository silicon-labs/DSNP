/*
 * Copyright (c) 2010-2011, Adrian Thurston <thurston@complang.org>
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

#include "string.h"
#include "dsnp.h"
#include "buffer.h"
#include "error.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>

void Buffer::bufferOverflow()
{
	throw ParseBufferExhausted();
}

Allocated stringStartEnd( const char *s, const char *e )
{
	long length = e-s;
	char *result = (char*)malloc( length+1 );
	memcpy( result, s, length );
	result[length] = 0;
	return Allocated( result, length );
}

Allocated timeNow()
{
	/* Get the current time. */
	time_t curTime = time(NULL);

	/* Convert to struct tm. */
	struct tm curTM;
	struct tm *tmRes = localtime_r( &curTime, &curTM );
	if ( tmRes == 0 )
		return Allocated( 0, 0 );

	/* Format for the message. */
	char *timeStr = new char[64];
	long length = strftime( timeStr, 64, "%Y-%m-%d %H:%M:%S", &curTM );
	if ( length == 0 ) 
		return Allocated( 0, 0 );
	
	return Allocated( timeStr, length );
}

Allocated concatenate( int n, ... )
{
	char *data = 0;
	long length = 0;

	va_list args;

	/* First pass to discover total length. */
	va_start( args, n );
	for ( int i = 0; i < n; i++ ) {
		String *s = va_arg( args, String* );
		length += s->length;
	}
	va_end( args );

	/* Second pass to construct the result. */
	if ( length >= 0 )  {
		data = new char[ length+1 ];
		char *dest = data;
		va_start( args, n );

		for ( int i = 0; i < n; i++ ) {
			String *s = va_arg( args, String* );
			memcpy( dest, s->data, s->length );
			dest += s->length;
		}

		va_end( args );
	}

	return Allocated( data, length );
}

Allocated::Allocated( char *data, long length )
:
	data(data),
	length(length)
{}

Pointer::Pointer( const char *data, long length )
:
	data(data),
	length(length)
{}

Pointer::Pointer( const char *data )
:
	data(data),
	length(strlen(data))
{}



String::String( const String &o )
:
	data(0),
	length(0)
{
	set( o.data, o.length );
}

String::String( const Allocated &as )
:
	data(as.data),
	length(as.length)
{}

String::String( const Pointer &ps )
{
	length = ps.length;
	data = new char[ ps.length+1 ];
	memcpy( data, ps.data, ps.length );
	data[length] = 0;
}

String::String( long size )
:
	data(0),
	length(0)
{
	allocate( size );
}

String::String( const Format &, const char *fmt, ... )
:
	data(0),
	length(0)
{
	va_list args;
	char buf[1];

	va_start( args, fmt );
	long len = vsnprintf( buf, 0, fmt, args );
	va_end( args );

	if ( len >= 0 )  {
		length = len;
		data = new char[ length+1 ];
		va_start( args, fmt );
		vsnprintf( data, length+1, fmt, args );
		va_end( args );
	}
}

String::~String()
{
	if ( data != 0 )
		delete[] data;
}

void String::operator=(const Allocated &as)
{
	if ( data != 0 )
		delete[] data;
	
	data = as.data;
	length = as.length;
}

void String::operator=(const Pointer &ps)
{
	if ( data != 0 )
		delete[] data;

	length = ps.length;
	data = new char[ ps.length+1 ];
	memcpy( data, ps.data, ps.length );
	data[length] = 0;
}

void String::set( const char *s, long l )
{
	if ( data != 0 )
		delete[] data;

	length = l;
	data = new char[ length+1 ];
	memcpy( data, s, length );
	data[length] = 0;
}

void String::set( const Buffer &buffer )
{
	if ( data != 0 )
		delete[] data;

	length = buffer.length;
	data = new char[ length+1 ];
	memcpy( data, buffer.data, length );
	data[length] = 0;
}

void String::set( const char *s, const char *e )
{
	if ( data != 0 )
		delete[] data;

	length = e-s;
	data = new char[ length+1 ];
	memcpy( data, s, length );
	data[length] = 0;
}

void String::set( const char *s )
{
	if ( data != 0 )
		delete[] data;

	if ( s == 0 ) {
		length = 0;
		data = 0;
	}
	else {
		length = strlen( s );
		data = new char[ length+1 ];
		memcpy( data, s, length );
		data[length] = 0;
	}
}

void String::set( const String &s )
{
	if ( data != 0 )
		delete[] data;

	if ( s.data == 0 ) {
		length = 0;
		data = 0;
	}
	else {
		length = s.length;
		data = new char[length+1];
		memcpy( data, s.data, length );
		data[length] = 0;
	}
}

/* Make string ready for size bytes. */
void String::allocate( long size )
{
	if ( data != 0 )
		delete[] data;
	data = new char[size+1];
	length = size;
	data[length] = 0;
}

void String::format( const char *fmt, ... )
{
	if ( data != 0 )
		delete[] data;
	data = 0;
	length = 0;

	va_list args;
	char buf[1];

	va_start( args, fmt );
	long len = vsnprintf( buf, 0, fmt, args );
	va_end( args );

	if ( len >= 0 )  {
		length = len;
		data = new char[ length+1 ];
		va_start( args, fmt );
		vsnprintf( data, length+1, fmt, args );
		va_end( args );
	}
}

void String::clear()
{
	if ( data != 0 ) {
		delete[] data;
		data = 0;
	}
	length = 0;
}

void String::addBody( const String &body )
{
	long totalLength = this->length + body.length + 2;
	char *result = new char[totalLength+1];
	char *dest = result;

	/* Copy in the existing message. */
	memcpy( dest, this->data, this->length );
	dest += this->length;

	/* Copy in the body. */
	memcpy( dest, body.data, body.length );
	dest += body.length;

	/* Terminate. */
	memcpy( dest, "\r\n", 2 );
	result[totalLength] = 0;

	/* Store the new message in place of the current. */
	delete[] data;
	data = result;
	length = totalLength;
}

void String::toLower()
{
	for ( int i = 0; i < length; i++ )
		data[i] = tolower( data[i] );
}

bool operator ==( const String &a, const String &b )
{
	if ( a.length != b.length )
		return false;
	else if ( a.length > 0 && memcmp( a.data, b.data, a.length ) != 0 )
		return false;

	return true;
}

bool operator !=( const String &a, const String &b )
{
	if ( a.length != b.length )
		return true;
	else if ( a.length > 0 && memcmp( a.data, b.data, a.length ) != 0 )
		return true;

	return false;
}
