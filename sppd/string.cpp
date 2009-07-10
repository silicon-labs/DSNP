#include "string.h"

#include <stdlib.h>
#include <string.h>

char *alloc_string( const char *s, const char *e )
{
	long length = e-s;
	char *result = (char*)malloc( length+1 );
	memcpy( result, s, length );
	result[length] = 0;
	return result;
}


String::String( const char *s, const char *e )
{
	length = e-s;
	data = new char[ length+1 ];
	memcpy( data, s, length );
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

String::~String()
{
	if ( data != 0 )
		delete[] data;
}

