#include "string.h"
#include "sppd.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdarg.h>
#include <stdio.h>

AllocString stringStartEnd( const char *s, const char *e )
{
	long length = e-s;
	char *result = (char*)malloc( length+1 );
	memcpy( result, s, length );
	result[length] = 0;
	return AllocString( result, length );
}

AllocString::AllocString( char *data, long length )
	: data(data), length(length)
{}

char *alloc_string( const char *s, const char *e )
{
	long length = e-s;
	char *result = (char*)malloc( length+1 );
	memcpy( result, s, length );
	result[length] = 0;
	return result;
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

String::String( const AllocString &as )
:
	data(as.data),
	length(as.length)
{}

void String::allocate( long size )
{
	data = new char[size];
}

String::String( const char *fmt, ... )
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

void String::clear()
{
	if ( data != 0 ) {
		delete[] data;
		data = 0;
	}
	length = 0;
}

String::~String()
{
	if ( data != 0 )
		delete[] data;
}

