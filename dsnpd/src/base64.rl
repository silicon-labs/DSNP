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
#include <string.h>

Allocated binToBase64( const u_char *data, long len )
{
	const char *index = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	long group;

	long lenRem = len % 3;
	long lenEven = len - lenRem;
	long allocLen = ( lenEven / 3 ) * 4 + ( lenRem > 0 ? 4 : 0 ) + 1;

	char *output = new char[allocLen];
	char *dest = output;

	for ( int i = 0; i < lenEven; i += 3 ) {
		group = (long)data[i] << 16;
		group |= (long)data[i+1] << 8;
		group |= (long)data[i+2];

		*dest++ = index[( group >> 18 ) & 0x3f];
		*dest++ = index[( group >> 12 ) & 0x3f];
		*dest++ = index[( group >> 6 ) & 0x3f];
		*dest++ = index[group & 0x3f];
	}

	if ( lenRem > 0 ) {
		group = (long)data[lenEven] << 16;
		if ( lenRem > 1 )
			group |= (long)data[lenEven+1] << 8;

		/* Always need the first two six-bit groups.  */
		*dest++ = index[( group >> 18 ) & 0x3f];
		*dest++ = index[( group >> 12 ) & 0x3f];
		if ( lenRem > 1 )
			*dest++ = index[( group >> 6 ) & 0x3f];
	}

	/* Compute the length, then null terminate. */
	int outLen = dest - output;
	*dest = 0;

	return Allocated( output, outLen );
}

%%{
	machine base64;
	write data;
}%%

Allocated base64ToBin( const char *src, long srcLen )
{
	long sixBits;
	long group;

	long lenRem = srcLen % 4;
	long lenEven = srcLen - lenRem;
	long allocLen = ( lenEven / 4 ) * 3 + ( lenRem > 0 ? 3 : 0 ) + 1;

	unsigned char *output = new u_char[allocLen];
	unsigned char *dest = output;

	/* Parser for response. */
	%%{
		action upperChar { sixBits = *p - 'A'; }
		action lowerChar { sixBits = 26 + (*p - 'a'); }
		action digitChar { sixBits = 52 + (*p - '0'); }
		action dashChar  { sixBits = 62; }
		action underscoreChar { sixBits = 63; }

		sixBits = 
			[A-Z] @upperChar |
			[a-z] @lowerChar |
			[0-9] @digitChar |
			'-' @dashChar |
			'_' @underscoreChar;

		action c1 {
			group = sixBits << 18;
		}
		action c2 {
			group |= sixBits << 12;
		}
		action c3 {
			group |= sixBits << 6;
		}
		action c4 {
			group |= sixBits;
		}

		action three {
			*dest++ = ( group >> 16 ) & 0xff;
			*dest++ = ( group >> 8 ) & 0xff;
			*dest++ = group & 0xff;
		}
		action two {
			*dest++ = ( group >> 16 ) & 0xff;
			*dest++ = ( group >> 8 ) & 0xff;
		}
		action one {
			*dest++ = ( group >> 16 ) & 0xff;
		}

		group =
			( sixBits @c1 sixBits @c2 sixBits @c3 sixBits @c4 ) %three;

		short =
			( sixBits @c1 sixBits @c2 sixBits ) %two |
			( sixBits @c1 sixBits ) %one ;

		# Lots of ambiguity, but duplicate removal makes it okay.
		main := group* short?;
			
	}%%

	/* Note: including the null. */
	const char *p = src;
	const char *pe = src + srcLen;
	const char *eof = pe;
	int cs;

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw Base64ParseError();

	/* Compute the length, then null terminate. */
	int outLen = dest - output;
	*dest = 0;

	return Allocated( (char*)output, outLen );
}
