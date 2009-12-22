#include "string.h"
#include "dsnp.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

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

char *allocString( const char *s, const char *e )
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

void String::set( const char *s )
{
	if ( data != 0 )
		delete[] data;

	length = strlen( s );
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

String::~String()
{
	if ( data != 0 )
		delete[] data;
}


AllocString timeNow()
{
	/* Get the current time. */
	time_t curTime = time(NULL);

	/* Convert to struct tm. */
	struct tm curTM;
	struct tm *tmRes = localtime_r( &curTime, &curTM );
	if ( tmRes == 0 )
		return AllocString( 0, 0 );

	/* Format for the message. */
	char *timeStr = new char[64];
	long length = strftime( timeStr, 64, "%Y-%m-%d %H:%M:%S", &curTM );
	if ( length == 0 ) 
		return AllocString( 0, 0 );
	
	return AllocString( timeStr, length );
}

AllocString addMessageData( const String &root, const char *msg, long mLen )
{
	long totalLength = root.length + mLen + 2;
	char *result = new char[totalLength+1];
	memcpy( result, root.data, root.length );
	memcpy( result + root.length, msg, mLen );
	memcpy( result + root.length + mLen, "\r\n", 2 );
	result[root.length + mLen + 2] = 0;
	return AllocString( result, totalLength );
}
