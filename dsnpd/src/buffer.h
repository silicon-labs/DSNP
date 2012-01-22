/*
 * Copyright (c) 2011, Adrian Thurston <thurston@complang.org>
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

#ifndef _BUFFER_H
#define _BUFFER_H

#include <string.h>

/* An automatically grown buffer for collecting tokens. Always reuses space;
 * never down resizes. */
struct Buffer
{
	Buffer()
	:
		limit(defaultLimit)
	{
		data = new char[initialSize];
		allocated = initialSize;
		length = 0;
	}
	~Buffer() { delete[] data; }

	void append( char p )
	{
		if ( length < limit ) {
			if ( length == allocated ) {
				allocated *= 2;
				char *newData = new char[allocated];
				memcpy( newData, data, length );
				delete[] data;
				data = newData;
			}
			data[length++] = p;
		}
		else {
			/* This will throw, but we can't do it inline without a circular
			 * include. */
			bufferOverflow();
		}
	}

	void allocate( long newLength )
	{
		if ( length < limit ) {
			if ( newLength > allocated ) {
				allocated = newLength;
				char *newData = new char[allocated];
				memcpy( newData, data, length );
				delete[] data;
				data = newData;
			}
			length = newLength;
		}
		else {
			/* This will throw, but we can't do it inline without a circular
			 * include. */
			bufferOverflow();
		}
	}

	void bufferOverflow();
	void clear() { length = 0; }

	/* 1K initial size, 8K limit for tokens. There are some cases where we have
	 * encryption parameters being passed through tokens. Need to sort that out
	 * and choose a smaller limit here. */
	static const long long initialSize = 1024;
	static const long long defaultLimit = 8 * initialSize;
	long long limit;

	char *data;
	int allocated;
	int length;
};

#endif /* _BUFFER_H */
