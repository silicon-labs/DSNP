#ifndef _LSTRING_H
#define _LSTRING_H

char *alloc_string( const char *s, const char *e );

struct String
{
	String()
		: data(0), length(0)
	{}

	operator char*() { return data; }

	String( const char *p1, const char *p2 );
	String( const char *fmt, ... );
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
