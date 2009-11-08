/*
 * Copyright (c) 2008-2009, Adrian Thurston <thurston@complang.org>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/bio.h>
#include "dsnpd.h"
#include "string.h"

#define MAX_MSG_LEN 16384

bool gblKeySubmitted = false;

/* FIXME: check all scanned lengths for overflow. */

%%{
	machine common;

	base64 = [A-Za-z0-9\-_]+;

	user = [a-zA-Z0-9_.]+     >{mark=p;} %{user.set(mark, p);};
	pass = graph+             >{mark=p;} %{pass.set(mark, p);};
	email = graph+            >{mark=p;} %{email.set(mark, p);};
	reqid = base64            >{mark=p;} %{reqid.set(mark, p);};
	hash = base64             >{mark=p;} %{hash.set(mark, p);};
	key = base64              >{mark=p;} %{key.set(mark, p);};
	sym = base64              >{mark=p;} %{sym.set(mark, p);};
	relid = base64            >{mark=p;} %{relid.set(mark, p);};
	token = base64            >{mark=p;} %{token.set(mark, p);};
	id_salt = base64          >{mark=p;} %{id_salt.set(mark, p);};
	requested_relid = base64  >{mark=p;} %{requested_relid.set(mark, p);};
	returned_relid = base64   >{mark=p;} %{returned_relid.set(mark, p);};

	date = ( 
		digit{4} '-' digit{2} '-' digit{2} ' ' 
		digit{2} ':' digit{2} ':' digit{2} 
	)
	>{mark=p;} %{date.set(mark, p);};

	path_part = (graph-'/')+;

	identity = 
		( 'https://' path_part '/' ( path_part '/' )* )
		>{mark=p;} %{identity.set(mark, p);};

	generation = [0-9]+       
		>{mark=p;} 
		%{
			gen_str.set(mark, p);
			generation = strtoll( gen_str, 0, 10 );
		};

	number = [0-9]+           
		>{mark=p;}
		%{
			number_str.set(mark, p);
			number = strtol( number_str, 0, 10 );
		};

	length = [0-9]+           
		>{mark=p;}
		%{
			length_str.set(mark, p);
			length = strtol( length_str, 0, 10 );
		};

	seq_num = [0-9]+          
		>{mark=p;}
		%{
			seq_str.set(mark, p);
			seq_num = strtoll( seq_str, 0, 10 );
		};

	EOL = '\r'? '\n';
}%%

%%{
	machine parser;

	include common;

	action set_config {
		set_config_by_uri( identity );

		/* Now that we have a config connect to the database. */
		mysql = db_connect();
		if ( mysql == 0 )
			fgoto *parser_error;
	}

	action comm_key {
		/* Check the authentication. */
		if ( strcmp( key, c->CFG_COMM_KEY ) == 0 )
			gblKeySubmitted = true;
		else
			fgoto *parser_error;
	}

	action check_key {
		if ( !gblKeySubmitted )
			fgoto *parser_error;
	}

	action check_ssl {
		if ( !ssl ) {
			message("ssl check failed\n");
			fgoto *parser_error;
		}
	}

	action start_tls {
		start_tls();
		ssl = true;
	}

	# Reads in a message block plus the terminating EOL.
	action read_message {
		/* Validate the length. */
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		/* Read in the message and the mandadory \r\r. */
		BIO_read( bioIn, message_buffer, length+2 );

		/* Parse just the \r\r. */
		p = message_buffer.data + length;
		pe = message_buffer.data + length + 2;
	}

	action term_data {
		message_buffer.data[length] = 0;
	}

	M_EOL = 
		EOL @read_message 
		EOL @term_data;

	commands := (
		'comm_key'i ' ' key EOL @comm_key |
		'start_tls'i EOL @start_tls |
		'login'i ' ' user ' ' pass 
			EOL @check_key @{
				login( mysql, user, pass );
			} |

		# Admin commands.
		'new_user'i ' ' user ' ' pass ' ' email
			EOL @check_key @{
				new_user( mysql, user, pass, email );
			} |

		# Public key sharing.
		'public_key'i ' ' user
			EOL @check_ssl @{
				public_key( mysql, user );
			} |

		# 
		# Friend Request.
		#
		'relid_request'i ' ' user ' ' identity
			EOL @check_key @{
				relid_request( mysql, user, identity );
			} |

		'relid_response'i ' ' user ' ' reqid ' ' identity
			EOL @check_key @{
				relid_response( mysql, user, reqid, identity );
			} |

		'friend_final'i ' ' user ' ' reqid ' ' identity
			EOL @check_key @{
				friend_final( mysql, user, reqid, identity );
			} |

		'fetch_requested_relid'i ' ' reqid
			EOL @check_ssl @{
				fetch_requested_relid( mysql, reqid );
			} |

		'fetch_response_relid'i ' ' reqid
			EOL @check_ssl @{
				fetch_response_relid( mysql, reqid );
			} |

		#
		# Friend Request Accept
		#
		'accept_friend'i ' ' user ' ' reqid
			EOL @check_key @{
				accept_friend( mysql, user, reqid );
			} |

		'prefriend_message'i ' ' relid ' ' length 
			M_EOL @check_ssl @{
				prefriend_message( mysql, relid, message_buffer.data );
			} |

		#
		# Friend login. 
		#
		'ftoken_request'i ' ' user ' ' hash
			EOL @check_key @{
				ftoken_request( mysql, user, hash );
			} |

		'ftoken_response'i ' ' user ' ' hash ' ' reqid
			EOL @check_key @{
				ftoken_response( mysql, user, hash, reqid );
			} |

		'fetch_ftoken'i ' ' reqid
			EOL @check_ssl @{
				fetch_ftoken( mysql, reqid );
			} |

		'submit_ftoken'i ' ' token
			EOL @check_key @{
				submit_ftoken( mysql, token );
			} |

		#
		# Broadcasting
		#
		'submit_broadcast'i ' ' user ' ' length 
			M_EOL @check_key @{
				submit_broadcast( mysql, user, message_buffer.data, length );
			} |

		#
		# Remote broadcasting
		#
		'remote_broadcast_request'i ' ' user ' ' identity ' ' hash ' ' token ' ' length
			M_EOL @check_key @{
				remote_broadcast_request( mysql, user, identity, hash, 
						token, message_buffer.data, length );
			} |

		'remote_broadcast_response'i ' ' user ' ' reqid
			EOL @check_key @{
				remote_broadcast_response( mysql, user, reqid );
			} |

		'remote_broadcast_final'i ' ' user ' ' reqid
			EOL @check_key @{
				remote_broadcast_final( mysql, user, reqid );
			} |

		#
		# Message sending.
		#
		'message'i ' ' relid ' ' length 
			M_EOL @check_ssl @{
				receive_message( mysql, relid, message_buffer.data );
			} |

		'broadcast'i ' ' relid ' ' generation ' ' length
			M_EOL @check_ssl @{
				broadcast( mysql, relid, generation, message_buffer.data );
			}
	)*;

	main := 'SPP/0.1'i ' ' identity %set_config EOL @{ fgoto commands; };
}%%

%% write data;

const long linelen = 4096;

int server_parse_loop()
{
	long cs;
	const char *mark;
	String user, pass, email, identity; 
	String length_str, reqid;
	String hash, key, relid, token, sym;
	String gen_str, seq_str;
	long length;
	long long generation;
	String message_buffer;
	message_buffer.allocate( MAX_MSG_LEN + 2 );

	MYSQL *mysql = 0;
	bool ssl = false;

	%% write init;

	while ( true ) {
		static char buf[linelen];
		int result = BIO_gets( bioIn, buf, linelen );

		/* Just break when client closes the connection. */
		if ( result <= 0 ) {
			message("parse_loop: exiting %d\n", result );
			break;
		}

		/* Did we get a full line? */
		long lineLen = strlen( buf );
		if ( buf[lineLen-1] != '\n' ) {
			error( "line too long\n" );
			return ERR_LINE_TOO_LONG;
		}

		message("parse_loop: parsing a line: %s", buf );

		const char *p = buf, *pe = buf + lineLen;
		%% write exec;

		BIO_flush( bioOut );

		if ( cs == parser_error ) {
			error( "parse error: %s", buf );
			return ERR_PARSE_ERROR;
		}
		else if ( cs < %%{ write first_final; }%% ) {
			return ERR_UNEXPECTED_END;
		}
	}

	if ( mysql != 0 ) {
		run_broadcast_queue_db( mysql );
		run_message_queue_db( mysql );
	}

	return 0;
}

/*
 * prefriend_message_parser
 */

%%{
	machine prefriend_message_parser;

	include common;

	main :=
		'notify_accept'i ' ' id_salt ' ' requested_relid ' ' returned_relid EOL @{
			notify_accept( mysql, user, friend_id, id_salt, requested_relid, returned_relid );
		} |
		'registered'i ' ' requested_relid ' ' returned_relid EOL @{
			registered( mysql, user, friend_id, requested_relid, returned_relid );
		};

}%%

%% write data;

int prefriend_message_parser( MYSQL *mysql, const char *relid,
		const char *user, const char *friend_id, const char *message )
{
	long cs;
	const char *mark;
	String id_salt, requested_relid, returned_relid;

	%% write init;

	const char *p = message;
	const char *pe = message + strlen( message );

	%% write exec;

	if ( cs < %%{ write first_final; }%% ) {
		if ( cs == parser_error )
			return ERR_PARSE_ERROR;
		else
			return ERR_UNEXPECTED_END;
	}

	return 0;
}

/*
 * message_parser
 */

%%{
	machine message_parser;

	include common;

	main := (
		'broadcast_key'i ' ' generation ' ' key 
			EOL @{
				broadcast_key( mysql, to_relid, user, friend_id, generation, key );
			} |
		'forward_to'i ' ' number ' ' generation ' ' identity ' ' relid
			EOL @{
				forward_to( mysql, user, friend_id, number, generation, identity, relid );
		} |
		'encrypt_remote_broadcast'i ' ' token ' ' seq_num ' ' length 
			EOL @{ msg = p+1; p += length; } 
			EOL @{
				/* Rest of the input is the msssage. */
				encrypt_remote_broadcast( mysql, user, friend_id, token, seq_num, msg );
			} |
		'return_remote_broadcast'i ' ' reqid ' ' generation ' ' sym
			EOL @{
				return_remote_broadcast( mysql, user, friend_id, reqid, generation, sym );
			}
	)*;
}%%

%% write data;

int message_parser( MYSQL *mysql, const char *to_relid,
		const char *user, const char *friend_id, const char *msg )
{
	long cs;
	const char *mark;
	String identity, number_str, key, relid, gen_str;
	String sym, token, reqid, seq_str, length_str;
	long length, number;
	long long seq_num, generation;

	message( "message parser: parsing: %s\n", msg );

	%% write init;

	const char *p = msg;
	const char *pe = msg + strlen( msg );

	%% write exec;

	if ( cs < %%{ write first_final; }%% ) {
		message("message_parser: parse error\n");
		if ( cs == parser_error )
			return ERR_PARSE_ERROR;
		else
			return ERR_UNEXPECTED_END;
	}

	return 0;
}

/*
 * broadcast_parser
 */

%%{
	machine broadcast_parser;

	include common;

	action direct_broadcast {
		if ( length > MAX_MSG_LEN ) {
			message("message too large\n");
			fgoto *parser_error;
		}

		/* Rest of the input is the msssage. */
		const char *msg = p + 1;
		direct_broadcast( mysql, relid, user, friend_id, seq_num, date, msg, length );
		fbreak;
	}

	action remote_broadcast {
		if ( length > MAX_MSG_LEN ) {
			message("message too large\n");
			fgoto *parser_error;
		}

		/* Rest of the input is the msssage. */
		const char *msg = p + 1;
		remote_broadcast( mysql, relid, user, friend_id, hash, generation, msg, length );
		fbreak;
	}

	main :=
		'direct_broadcast'i ' ' seq_num ' ' date ' ' length EOL @direct_broadcast |
		'remote_broadcast'i ' ' hash ' ' generation ' ' seq_num ' ' length EOL @remote_broadcast;
}%%

%% write data;

int broadcast_parser( long long &ret_seq_num, MYSQL *mysql, const char *relid,
		const char *user, const char *friend_id, const char *msg, long mLen )
{
	long cs;
	const char *mark;
	String date, length_str, hash;
	String seq_str, gen_str;
	long length;
	long long generation, seq_num;

	//message("parsing broadcast string: %s\n", msg );

	%% write init;

	const char *p = msg;
	const char *pe = msg + mLen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% ) {
		if ( cs == parser_error )
			return ERR_PARSE_ERROR;
		else
			return ERR_UNEXPECTED_END;
	}

	ret_seq_num = seq_num;
	return 0;
}

/*
 * remote_broadcast_parser
 */

%%{
	machine remote_broadcast_parser;

	include common;

	action remote_inner {
		if ( length > MAX_MSG_LEN ) {
			message("message too large\n");
			fgoto *parser_error;
		}

		/* Rest of the input is the msssage. */
		const char *msg = p + 1;
		remote_inner( mysql, user, subject_id, author_id, seq_num, date, msg, length );
		fbreak;
	}

	main :=
		'remote_inner'i ' ' seq_num ' ' date ' ' length EOL @remote_inner;

}%%

%% write data;

int remote_broadcast_parser( MYSQL *mysql, const char *user,
		const char *subject_id, const char *author_id, const char *msg, long mLen )
{
	long cs;
	const char *mark;
	String date, length_str, seq_str;
	long long seq_num;
	long length;

	message("parsing remote_broadcast string: %.*s\n", (int)mLen, msg );

	%% write init;

	const char *p = msg;
	const char *pe = msg + mLen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% ) {
		if ( cs == parser_error )
			return ERR_PARSE_ERROR;
		else
			return ERR_UNEXPECTED_END;
	}

	return 0;
}

/*
 * notify_accept_result_parser
 */

%%{
	machine notify_accept_result_parser;

	include common;

	main :=
		'returned_id_salt'i ' ' token EOL @{
			notify_accept_returned_id_salt( mysql, user, user_reqid, 
				from_id, requested_relid, returned_relid, token );
		};
}%%

%% write data;

int notify_accept_result_parser( MYSQL *mysql, const char *user, const char *user_reqid, 
		const char *from_id, const char *requested_relid, const char *returned_relid, const char *msg )
{
	long cs;
	const char *mark;
	String token;

	%% write init;

	const char *p = msg;
	const char *pe = msg + strlen( msg );

	%% write exec;

	if ( cs < %%{ write first_final; }%% ) {
		if ( cs == parser_error )
			return ERR_PARSE_ERROR;
		else
			return ERR_UNEXPECTED_END;
	}

	return 0;
}

/*
 * fetch_public_key_net
 */

%%{
	machine public_key;
	write data;
}%%

long fetch_public_key_net( PublicKey &pub, const char *site, 
		const char *host, const char *user )
{
	static char buf[8192];
	long cs;
	const char *p, *pe;
	bool OK = false;
	const char *mark;
	String n, e;

	TlsConnect tlsConnect;
	int result = tlsConnect.connect( host, site );
	if ( result < 0 ) 
		return result;

	message( "fetching public key for %s from host %s site %s\n", user, host, site );

	BIO_printf( tlsConnect.sbio, "public_key %s\r\n", user );
	BIO_flush( tlsConnect.sbio );

	/* Read the result. */
	int readRes = BIO_gets( tlsConnect.sbio, buf, 8192 );
	message("encrypted return to fetch_public_key_net is %s", buf );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		return ERR_READ_ERROR;

	/* Parser for response. */
	%%{
		include common;

		n = base64   >{mark = p;} %{n.set(mark, p);};
		e = base64   >{mark = p;} %{e.set(mark, p);};

		main := 
			'OK ' n ' ' e EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return ERR_PARSE_ERROR;
	
	if ( ! OK )
		return ERR_SERVER_ERROR;
	
	pub.n = n.relinquish();
	pub.e = e.relinquish();

	message("fetch_public_key_net returning %s %s\n", pub.n, pub.e );

	return 0;
}

/*
 * fetch_requested_relid_net
 */

%%{
	machine fr_relid;
	write data;
}%%


long fetch_requested_relid_net( RelidEncSig &encsig, const char *site, 
		const char *host, const char *fr_reqid )
{
	static char buf[8192];
	long cs;
	const char *p, *pe;
	bool OK = false;
	const char *mark;
	String sym;

	TlsConnect tlsConnect;
	int result = tlsConnect.connect( host, site );
	if ( result < 0 ) 
		return result;

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, "fetch_requested_relid %s\r\n", fr_reqid );
	BIO_flush( tlsConnect.sbio );

	/* Read the result. */
	int readRes = BIO_gets( tlsConnect.sbio, buf, 8192 );
	message("encrypted return to fetch_requested_relid is %s", buf );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		return ERR_READ_ERROR;

	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' sym EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return ERR_PARSE_ERROR;
	
	if ( !OK )
		return ERR_SERVER_ERROR;
	
	encsig.sym = sym.relinquish();

	return 0;
}


/*
 * fetch_response_relid_net
 */

%%{
	machine relid;
	write data;
}%%

long fetch_response_relid_net( RelidEncSig &encsig, const char *site,
		const char *host, const char *reqid )
{
	static char buf[8192];
	long cs;
	bool OK = false;
	const char *p, *pe;
	const char *mark;
	String sym;

	TlsConnect tlsConnect;
	int result = tlsConnect.connect( host, site );
	if ( result < 0 ) 
		return result;

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, "fetch_response_relid %s\r\n", reqid );
	BIO_flush( tlsConnect.sbio );

	/* Read the result. */
	int readRes = BIO_gets( tlsConnect.sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		return ERR_READ_ERROR;

	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' sym EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return ERR_PARSE_ERROR;
	
	if ( ! OK )
		return ERR_SERVER_ERROR;
	
	encsig.sym = sym.relinquish();

	return 0;
}

/*
 * fetch_ftoken_net
 */

%%{
	machine ftoken;
	write data;
}%%

long fetch_ftoken_net( RelidEncSig &encsig, const char *site,
		const char *host, const char *flogin_reqid )
{
	static char buf[8192];
	long cs;
	bool OK = false;
	const char *p, *pe;
	const char *mark;
	String sym;

	TlsConnect tlsConnect;
	int result = tlsConnect.connect( host, site );
	if ( result < 0 ) 
		return result;

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, "fetch_ftoken %s\r\n", flogin_reqid );
	BIO_flush( tlsConnect.sbio );

	/* Read the result. */
	int readRes = BIO_gets( tlsConnect.sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		return ERR_READ_ERROR;

	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' sym EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return ERR_PARSE_ERROR;
	
	if ( ! OK )
		return ERR_SERVER_ERROR;
	
	encsig.sym = sym.relinquish();

	return 0;
}


/*
 * Identity::parse()
 */

%%{
	machine identity;
	write data;
}%%

long Identity::parse()
{
	long result = 0, cs;
	const char *p, *pe, *eof;
	const char *i1, *i2;
	const char *h1, *h2;
	const char *pp1, *pp2;

	/* Parser for response. */
	%%{
		path_part = (graph-'/')+ >{pp1=p;} %{pp2=p;};

		main :=
			( 'https://' path_part >{h1=p;} %{h2=p;} '/' ( path_part '/' )* )
			>{i1=p;} %{i2=p;};
	}%%

	p = identity;
	pe = p + strlen(identity);
	eof = pe;

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return ERR_PARSE_ERROR;
	
	host = alloc_string( h1, h2 );
	user = alloc_string( pp1, pp2 );

	/* We can use the last path part to get the site. */
	site = alloc_string( identity, pp1 );

	return result;
}

/*
 * send_broadcast_net
 */

%%{
	machine send_broadcast_net;
	write data;
}%%

long send_broadcast_net( MYSQL *mysql, const char *to_site, const char *to_relid,
		long long to_generation, const char *msg, long mLen )
{
	static char buf[8192];
	long cs;
	const char *p, *pe;
	bool OK = false;
	long pres;
	String relid, gen_str, seq_str;

	/* Need to parse the identity. */
	Identity site( to_site );
	pres = site.parse();

	if ( pres < 0 )
		return pres;

	TlsConnect tlsConnect;
	int result = tlsConnect.connect( site.host, to_site );
	if ( result < 0 ) 
		return result;

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, 
		"broadcast %s %lld %ld\r\n", 
		to_relid, to_generation, mLen );
	BIO_write( tlsConnect.sbio, msg, mLen );
	BIO_write( tlsConnect.sbio, "\r\n", 2 );
	BIO_flush( tlsConnect.sbio );

	/* Read the result. */
	int readRes = BIO_gets( tlsConnect.sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		return ERR_READ_ERROR;

	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK' EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return ERR_PARSE_ERROR;
	
	if ( !OK )
		return ERR_SERVER_ERROR;
	
	return 0;
}

/*
 * send_message_net
 */

%%{
	machine send_message_net;
	write data;
}%%

long send_message_net( MYSQL *mysql, bool prefriend, const char *from_user,
		const char *to_identity, const char *relid, const char *message,
		long mLen, char **result_message )
{
	static char buf[8192];
	long cs;
	const char *p, *pe;
	bool OK = false;
	long pres;
	const char *mark;
	String length_str, token;
	long length;

	/* Initialize the result. */
	if ( result_message != 0 ) 
		*result_message = 0;

	/* Need to parse the identity. */
	Identity toIdent( to_identity );
	pres = toIdent.parse();

	if ( pres < 0 )
		return pres;

	TlsConnect tlsConnect;
	int result = tlsConnect.connect( toIdent.host, toIdent.site );
	if ( result < 0 ) 
		return result;

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, "%smessage %s %ld\r\n", prefriend ? "prefriend_" : "", relid, mLen );
	BIO_write( tlsConnect.sbio, message, mLen );
	BIO_write( tlsConnect.sbio, "\r\n", 2 );
	BIO_flush( tlsConnect.sbio );

	/* Read the result. */
	int readRes = BIO_gets( tlsConnect.sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		return ERR_READ_ERROR;

	/* Parser for response. */
	%%{
		include common;

		action result {
			if ( length > MAX_MSG_LEN )
				fgoto *parser_error;

			char *user_message = new char[length+1];
			BIO_read( tlsConnect.sbio, user_message, length );
			user_message[length] = 0;

			::message( "about to decrypt RESULT\n" );

			if ( result_message != 0 ) 
				*result_message = decrypt_result( mysql, from_user, to_identity, user_message );
			::message( "finished with decrypt RESULT\n" );
			OK = true;
		}

		action token {
			::message("got back a reqid\n");
			char *user_message = new char[token.length+1];
			memcpy( user_message, token.data, token.length );
			user_message[token.length] = 0;
			*result_message = user_message;
			OK = true;
		}

		main := 
			'OK' EOL @{ OK = true; } |
			'RESULT' ' ' length EOL @result |
			'REQID' ' ' token EOL @token |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return ERR_PARSE_ERROR;
	
	if ( !OK )
		return ERR_SERVER_ERROR;
	
	return 0;
}

/*
 * send_acknowledgement_net
 */

%%{
	machine send_acknowledgement_net;
	write data;
}%%

long send_acknowledgement_net( MYSQL *mysql, const char *to_site, const char *to_relid,
		long long to_generation, long long to_seq_num )
{
	static char buf[8192];
	long cs;
	const char *p, *pe;
	bool OK = false;
	long pres;

	/* Need to parse the identity. */
	Identity site( to_site );
	pres = site.parse();

	if ( pres < 0 )
		return pres;

	TlsConnect tlsConnect;
	int result = tlsConnect.connect( site.host, to_site );
	if ( result < 0 ) 
		return result;

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, 
		"acknowledgement %s %lld %lld\r\n", 
		to_relid, to_generation, to_seq_num );
	BIO_flush( tlsConnect.sbio );

	/* Read the result. */
	int readRes = BIO_gets( tlsConnect.sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		return ERR_READ_ERROR;

	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK' EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return ERR_PARSE_ERROR;
	
	if ( !OK )
		return ERR_SERVER_ERROR;
	
	return 0;
}
