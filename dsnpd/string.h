#ifndef _LSTRING_H
#define _LSTRING_H

#include <sys/types.h>
#include <openssl/bn.h>

char *allocString( const char *s, const char *e );

struct AllocString
{
	explicit AllocString( char *data, long length );

	operator char*() const { return data; }

	char *data;
	long length;
};

struct String
{
	String()
		: data(0), length(0)
	{}

	operator const char*() const { return data; }

	const char* operator()() const { return data; }

	void operator=(const char *src) { set(src); }

	String( const char *fmt, ... );
	String( const AllocString &as );
	String( long size );

	~String();

	void clear();
	void allocate( long size );
	void set( const char *p1, const char *p2 );
	void set( const char *s );
	void format( const char *fmt, ... );

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

AllocString stringStartEnd( const char *s, const char *e );
AllocString timeNow();
AllocString addMessageData( const String &root, const char *msg, long mLen );

#endif
