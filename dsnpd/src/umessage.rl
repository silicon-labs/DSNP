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

#include "dsnp.h"
#include "encrypt.h"
#include "error.h"

%%{
	machine msg;
	include common "common.rl";

	CRLF = '\r\n';

    header_content_type =
        'Content-Type'i ': ' (
			'text/plain' |
			'image/jpg'
		)
		CRLF;

    header_type =
        'Type'i ': ' (
			'broadcast' |
			'board-post' |
			'name-change' |
			'photo-upload' |
			'photo-tag'
		)
		CRLF;

	header_date = 
		'Date'i ': '
		( 
			digit{4} '-' digit{2} '-' digit{2} ' ' 
			digit{2} ':' digit{2} ':' digit{2} 
		)
		CRLF;
	
	header_publisher_iduri =
		'Publisher-Iduri: 'i 
		iduri_def >clear $buf
			%{
				if ( publisher.length != 0 )
					throw ParseError( __FILE__, __LINE__ );
				publisher.set( buf );
			}
		CRLF;

	header_author_iduri =
		'Author-Iduri: 'i 
		iduri_def >clear $buf 
			%{
				if ( author.length != 0 )
					throw ParseError( __FILE__, __LINE__ );
				author.set( buf );
			}
		CRLF;

	header_subject_iduri =
		'Subject-Iduri: 'i 
		iduri_def >clear $buf %{ 
				buf.append( 0 );
				subjects.push_back( std::string(buf.data) );
			}
		CRLF;

	header_remote_presentation =
		'Remote-Presentation: 'i path CRLF;

	header_remote_resource =
		'Remote-Resource: 'i path CRLF;
	
	header_message_id =
		'Message-Id: 'i message_id CRLF;

	headers = 
	(
		header_content_type |
		header_type |
		header_date |
		header_publisher_iduri |
		header_subject_iduri |
		header_author_iduri |
		header_remote_presentation |
		header_remote_resource |
		header_message_id
	)*;

    main := 
		headers 
		CRLF @{ 
			/* Make sure we got a publisher and a message-id. */
			if ( publisher.length == 0 )
				throw ParseError( __FILE__, __LINE__ );
			if ( messageId.length == 0 )
				throw ParseError( __FILE__, __LINE__ );
		}
		any*;
}%%

%% write data;

Parser::Control UserMessageParser::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

