/*
 * Copyright (c) 2008-2011, Adrian Thurston <thurston@complang.org>
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

%%{
	machine common;

	alphtype unsigned char;

	action clear { buf.clear(); }
	action buf { buf.append(fc); }

	#
	# Suppored Versions
	#
	version_0_1 = 
		'0.1' %{
			v = VERSION_MASK_0_1;
		};

	version_0_2 = 
		'0.2' %{
			v = VERSION_MASK_0_2;
		};

	version_0_3 = 
		'0.3' %{
			v = VERSION_MASK_0_3;
		};

	version_0_4 = 
		'0.4' %{
			v = VERSION_MASK_0_4;
		};

	version_0_5 = 
		'0.5' %{
			v = VERSION_MASK_0_5;
		};

	version_0_6 = 
		'0.6' %{
			v = VERSION_MASK_0_6;
		};

	# --VERSION--
	version = ( 
			version_0_1 | version_0_2 | version_0_3 | 
			version_0_4 | version_0_5 | version_0_6 
	)
	%{
		if ( versions & v )
			throw VersionAlreadyGiven();

		versions |= v;
	};

	base64 = [A-Za-z0-9\-_]+;
	pass = graph+               >clear $buf %{ pass.set(buf); };
	reqid = base64              >clear $buf %{ reqid.set(buf); };
	hash = base64               >clear $buf %{ hash.set(buf); };
	key = base64                >clear $buf %{ key.set(buf); };
	sym = base64                >clear $buf %{ sym.set(buf); };
	relid = base64              >clear $buf %{ relid.set(buf); };
	token = base64              >clear $buf %{ token.set(buf); };
	login_token = base64        >clear $buf %{ loginToken.set(buf); };
	flogin_token = base64       >clear $buf %{ floginToken.set(buf); };
	id_salt = base64            >clear $buf %{ id_salt.set(buf); };
	dist_name = base64          >clear $buf %{ distName.set(buf); };
	private_name = graph+       >clear $buf %{ privateName.set(buf); };
	session_id = graph+         >clear $buf %{ sessionId.set(buf); };

	n = base64                  >clear $buf %{ n.set(buf); };
	e = base64                  >clear $buf %{ e.set(buf); };

	path_part = (graph-'/')+;

	rel_path = ( path_part '/' )* path_part?;

	path = '/' rel_path;

	scheme = 'dsnp';

	# FIXME: should not be requiring trailing slash.
	iduri_def = 
		scheme '://' path_part '/' rel_path;

	iduri = iduri_def
		>clear $buf %{ iduri.set(buf); };

	user = iduri_def
		>clear $buf %{ user.set(buf); };

	site = iduri_def
		>clear $buf %{ site.set(buf); };

	host = path_part
		>clear $buf %{ host.set(buf); };

	generation = [0-9]+       
		>clear $buf
		%{
			buf.append( 0 );
			generation = parseId( buf.data );
		};

	number = [0-9]+           
		>clear $buf
		%{
			buf.append( 0 );
			number = parseId( buf.data );
		};

	message_id =
		[a-zA-Z0-9\-\_\+\.]+
		>clear $buf
		${
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
		%{ messageId.set( buf ); };

	EOL = '\r'? '\n';

	# Always use this before M_EOL. Might be a good idea to include this in the
	# M_EOL definition, but then the message line would have a hidden
	# component.
	length = ( [0-9]+ - '0' )
		>clear $buf
		%{
			/* Note we must set counter here as well. All lengths are followed
			 * by some block of input. */
			buf.append( 0 );
			length = counter = parseLength( buf.data );

			/* Set the buffer limit temporarily. */
			buf.limit = length;
		};

	# Count down the length. Assumed to have counter set.
	action dec { --counter }
	nbytes = ( any when dec )* any when !dec;

	action collect_message {
		/* Take from the buf and reset the buf's limit. */
		body.set( buf );
		buf.clear();
		buf.limit = buf.defaultLimit;
	}
	
	# Must be preceded by use of a 'length' machine.
	M_EOL =
		EOL nbytes >clear $buf %collect_message EOL;

	# Non-zero unsigned, two bytes. Breakitdown.
	# Non-zero unsigned, two bytes. Breakitdown.
	nzuLen16 = 
		(
			( 0x01 .. 0xff ) @{ val = (u_long)*p << 8; }
			( any )          @{ val |= *p; }
		) |
		(
			( 0x00 )         @{ val = 0; }
			( 0x01 .. 0xff ) @{ val |= *p; }
		);

	bin16 = 
		nzuLen16 @{ 
			counter = val;
			buf.allocate( val );
			dest = (u_char*)buf.data;
		}
		nbytes ${ *dest++ = *p; };
	
	# Allow an empty block.
	bin16empty = 
		bin16 | 
		( 0 0 @{ buf.clear(); } );

	recipients =
		bin16 @{ recipients.set( buf ); };

	body =
		bin16 @{ body.set( buf ); };

	generation64 =
		any{8} 
		>{ generation = 0; } 
		${ 
			generation <<= 8;
			generation |= (uint8_t)*p;
		};

	dist_name0 = base64     >clear $buf 0 @{ distName.set( buf ); };
	reqid0 = base64         >clear $buf 0 @{ reqid.set( buf ); };
	relid0 = base64         >clear $buf 0 @{ relid.set( buf ); };
	token0 = base64         >clear $buf 0 @{ token.set( buf ); };
	hash0 = base64          >clear $buf 0 @{ hash.set( buf ); };

	message_id0 =
		[a-zA-Z0-9\-\_\+\.]+
		>clear $buf ${
			if ( buf.length > 64 )
				throw ParseError( __FILE__, __LINE__ );
		}
		0 @{ 
			messageId.set( buf );
		};

	iduri0 = 
		iduri_def >clear $buf 0 @{ iduri.set(buf); };

	user0 = 
		( iduri_def )
		>clear $buf 0 @{ user.set(buf); };
}%%
