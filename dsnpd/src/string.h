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

#ifndef _LSTRING_H
#define _LSTRING_H

#include <sys/types.h>
#include <openssl/bn.h>

struct Buffer;

struct Format
{
	Format() {}
};

/* This should only be used for strings allocated in the style of the String
 * class ( buffer[len+1], buffer[len] == 0 ).  */
struct Allocated
{
	explicit Allocated() : data(0), length(0) {}
	explicit Allocated( char *data, long length );

	char *data;
	long length;
};

struct Pointer
{
	explicit Pointer( const char *data, long length );
	explicit Pointer( const char *data );

	const char *data;
	long length;
};

struct String
{
	String()
	:
		data(0),
		length(0)
	{}

	/* We don't want this called by accident. Gotta ask for it. */
	String( const Format &, const char *fmt, ... );
	String( const Pointer &ps );
	String( const Allocated &as );
	String( const String &string );
	String( long size );

	~String();

	operator const char*() const { return data; }
	const char* operator()() const { return data; }
	void operator=(const char *src) { set(src); }
	void operator=(const String &s) { set(s); }
	void operator=(const Buffer &b) { set(b); }
	void operator=(const Allocated &as);
	void operator=(const Pointer &ps);

	void toLower();

	void clear();
	void allocate( long size );
	void set( const char *p1, const char *p2 );
	void set( const char *d, long length );
	void set( const char *s );
	void set( const Buffer &buffer );
	void set( const String &s );
	void format( const char *fmt, ... );

	u_char *binary() const { return (u_char*)data; }

	void addBody( const String &body );

	Allocated relinquish()
	{
		Allocated result( data, length );

		data = 0;
		length = 0;

		return result;
	}

	char *data;
	long length;
};

Allocated stringStartEnd( const char *s, const char *e );
Allocated timeNow();
Allocated addMessageData( const String &root, const char *msg, long mLen );

bool operator ==( const String &a, const String &b );
bool operator !=( const String &a, const String &b );

/* Takes pointers to strings. */
Allocated concatenate( int n, ... );

#endif
