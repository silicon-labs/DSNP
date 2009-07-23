#ifndef _LSTRING_H
#define _LSTRING_H

#include <sys/types.h>
#include <openssl/bn.h>

char *alloc_string( const char *s, const char *e );

struct AllocString
{
	AllocString( char *data, long length )
		: data(data), length(length) {}

	operator char*() const { return data; }

	char *data;
	long length;
};

struct String
{
	String()
		: data(0), length(0)
	{}

	operator char*() const { return data; }

	String( const char *p1, const char *p2 );
	String( const char *fmt, ... );
	String( const AllocString &as )
		: data(as.data), length(as.length) {}

	~String();

	void clear();
	void allocate( long size );
	void set( const char *p1, const char *p2 );
	void set( const char *fmt, ... );

	char *relinquish()
	{
		char *res = data;
		data = 0;
		length = 0;
		return res;
	}

	char *data;
	long length;
};

#endif
