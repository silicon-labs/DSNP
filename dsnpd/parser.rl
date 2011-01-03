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
#include "dsnp.h"
#include "string.h"
#include "error.h"

#define MAX_MSG_LEN 16384

bool gblKeySubmitted = false;

/* FIXME: check all scanned lengths for overflow. */

%%{
	machine common;

	base64 = [A-Za-z0-9\-_]+;

	user = [a-zA-Z0-9_.]+     >{mark=p;} %{user.set(mark, p);};
	pass = graph+             >{mark=p;} %{pass.set(mark, p);};
	reqid = base64            >{mark=p;} %{reqid.set(mark, p);};
	hash = base64             >{mark=p;} %{hash.set(mark, p);};
	key = base64              >{mark=p;} %{key.set(mark, p);};
	sym = base64              >{mark=p;} %{sym.set(mark, p);};
	sym1 = base64             >{mark=p;} %{sym1.set(mark, p);};
	sym2 = base64             >{mark=p;} %{sym2.set(mark, p);};
	relid = base64            >{mark=p;} %{relid.set(mark, p);};
	token = base64            >{mark=p;} %{token.set(mark, p);};
	id_salt = base64          >{mark=p;} %{id_salt.set(mark, p);};
	requested_relid = base64  >{mark=p;} %{requestedRelid.set(mark, p);};
	returned_relid = base64   >{mark=p;} %{returnedRelid.set(mark, p);};
	network = [a-zA-Z0-9_.\-]+  >{mark=p;} %{network.set(mark, p);};
	dist_name = base64        >{mark=p;} %{distName.set(mark, p);};

	date = ( 
		digit{4} '-' digit{2} '-' digit{2} ' ' 
		digit{2} ':' digit{2} ':' digit{2} 
	)
	>{mark=p;} %{date.set(mark, p);};

	path_part = (graph-'/')+;

	identity_pat = 
		( 'https://' path_part '/' ( path_part '/' )* );

	identity = identity_pat >{mark=p;} %{identity.set(mark, p);};
	identity1 = identity_pat >{mark=p;} %{identity1.set(mark, p);};
	identity2 = identity_pat >{mark=p;} %{identity2.set(mark, p);};

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

	action skip_message {
		if ( length > MAX_MSG_LEN ) {
			error("message too large\n");
			fgoto *parser_error;
		}

		/* Rest of the input is the msssage. */
		embeddedMsg = p + 1;
		p += length;
	}

	# Reads in a message block plus the terminating EOL.
	action read_message {
		/* Validate the length. */
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		/* Read in the message and the mandadory \r\r. */
		BIO_read( bioIn, message_buffer.data, length+2 );

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

}%%

%%{
	machine parser;

	include common;

	action set_config {
		setConfigByUri( identity );

		/* Now that we have a config connect to the database. */
		mysql = dbConnect();
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
		startTls();
		ssl = true;
	}

	commands := (
		'comm_key'i ' ' key EOL @comm_key |
		'start_tls'i EOL @start_tls |
		'login'i ' ' user ' ' pass 
			EOL @check_key @{
				login( mysql, user, pass );
			} |

		# Admin commands.
		'new_user'i ' ' user ' ' pass
			EOL @check_key @{
				newUser( mysql, user, pass );
			} |

		# Public key sharing.
		'public_key'i ' ' user
			EOL @check_ssl @{
				publicKey( mysql, user );
			} |

		# 
		# Friend Request.
		#
		'relid_request'i ' ' user ' ' identity
			EOL @check_key @{
				relidRequest( mysql, user, identity );
			} |

		'relid_response'i ' ' user ' ' reqid ' ' identity
			EOL @check_key @{
				relidResponse( mysql, user, reqid, identity );
			} |

		'friend_final'i ' ' user ' ' reqid ' ' identity
			EOL @check_key @{
				friendFinal( mysql, user, reqid, identity );
			} |

		'fetch_requested_relid'i ' ' reqid
			EOL @check_ssl @{
				fetchRequestedRelid( mysql, reqid );
			} |

		'fetch_response_relid'i ' ' reqid
			EOL @check_ssl @{
				fetchResponseRelid( mysql, reqid );
			} |

		#
		# Friend Request Accept
		#
		'accept_friend'i ' ' user ' ' reqid
			EOL @check_key @{
				acceptFriend( mysql, user, reqid );
			} |

		'prefriend_message'i ' ' relid ' ' length 
			M_EOL @check_ssl @{
				prefriendMessage( mysql, relid, message_buffer.data );
			} |

		#
		# Friend management.
		#
		'show_network'i ' ' user ' ' network
			EOL @check_key @{
				showNetwork( mysql, user, network );
			} |
		'unshow_network'i ' ' user ' ' network
			EOL @check_key @{
				unshowNetwork( mysql, user, network );
			} |
		'add_to_network'i ' ' user ' ' network ' ' identity
			EOL @check_key @{
				addToNetwork( mysql, user, network, identity );
			} |
		'remove_from_network'i ' ' user ' ' network ' ' identity
			EOL @check_key @{
				removeFromNetwork( mysql, user, network, identity );
			} |
			

		#
		# Friend login. 
		#
		'ftoken_request'i ' ' user ' ' hash
			EOL @check_key @{
				ftokenRequest( mysql, user, hash );
			} |

		'ftoken_response'i ' ' user ' ' hash ' ' reqid
			EOL @check_key @{
				ftokenResponse( mysql, user, hash, reqid );
			} |

		'fetch_ftoken'i ' ' reqid
			EOL @check_ssl @{
				fetchFtoken( mysql, reqid );
			} |

		'submit_ftoken'i ' ' token
			EOL @check_key @{
				submitFtoken( mysql, token );
			} |

		#
		# Broadcasting
		#
		'submit_broadcast'i ' ' user ' ' length 
			M_EOL @check_key @{
				submitBroadcast( mysql, user, message_buffer.data, length );
			} |

		#
		# Direct messages to friends
		#
		'submit_message'i ' ' user ' ' identity ' ' length
			M_EOL @check_key @{
				submitMessage( mysql, user, identity, message_buffer.data, length );
			} |

		#
		# Remote broadcasting
		#
		'remote_broadcast_request'i ' ' user ' ' identity ' ' hash ' ' token ' ' network ' ' length
			M_EOL @check_key @{
				remoteBroadcastRequest( mysql, user, identity, hash, 
						token, network, message_buffer.data, length );
			} |

		'remote_broadcast_response'i ' ' user ' ' reqid
			EOL @check_key @{
				remote_broadcast_response( mysql, user, reqid );
			} |

		'remote_broadcast_final'i ' ' user ' ' reqid
			EOL @check_key @{
				remoteBroadcastFinal( mysql, user, reqid );
			} |

		#
		# Message sending.
		#
		'message'i ' ' relid ' ' length 
			M_EOL @check_ssl @{
				receiveMessage( mysql, relid, message_buffer.data );
			} |

		'broadcast_recipient'i ' ' relid
			EOL @{
				broadcastReceipient( mysql, recipients, relid );
			} |

		'broadcast'i ' ' network ' ' generation ' ' length
			M_EOL @check_ssl @{
				receiveBroadcast( mysql, recipients, network, generation,
						message_buffer.data );
				recipients.clear();
			} |


		#
		# Testing
		#

		'send_all'i ' ' user ' ' network ' ' identity EOL @check_key @{
				//sendAllProofs( mysql, user, network, identity );
				//sendAllProofs2( mysql, user, network, identity );
				BIO_printf( bioOut, "OK\r\n" );
			} |

		( 'quit'i | 'exit'i )
			EOL @{
				exit = true;
			}
			
	)*;

	main := 'DSNP/0.1'i ' ' identity %set_config EOL @{ fgoto commands; };
}%%

%% write data;

const long linelen = 4096;

int serverParseLoop()
{
	long cs;
	const char *mark;
	String user, pass, email, identity; 
	String length_str, reqid;
	String hash, key, relid, token, sym;
	String gen_str, seq_str, network;
	long length;
	long long generation;
	String message_buffer;
	message_buffer.allocate( MAX_MSG_LEN + 2 );
	int retVal = 0;
	RecipientList recipients;

	MYSQL *mysql = 0;
	bool ssl = false;
	bool exit = false;

	%% write init;

	while ( true ) {
		static char buf[linelen];
		int result = BIO_gets( bioIn, buf, linelen );

		/* break when client closes the connection. */
		if ( result <= 0 )
			break;

		/* Did we get a full line? */
		long lineLen = strlen( buf );
		if ( buf[lineLen-1] != '\n' ) {
			error( "incomplete line, exiting\n" );
			retVal = ERR_LINE_TOO_LONG;
		}

		message( "command: %.*s", (int)lineLen, buf );

		const char *p = buf, *pe = buf + lineLen;
		%% write exec;

		(void)BIO_flush( bioOut );

		if ( exit )
			break;

		if ( cs == parser_error ) {
			error( "parse error, exiting\n" );
			retVal = ERR_PARSE_ERROR;
			break;
		}
		else if ( cs < %%{ write first_final; }%% ) {
			error( "incomplete line, exiting\n" );
			retVal = ERR_UNEXPECTED_END;
			break;
		}
	}

	if ( mysql != 0 )
		mysql_close( 0 );

	return retVal;
}

/*
 * notify_accept_result_parser
 */

%%{
	machine notify_accept_result_parser;

	include common;

	main :=
		'notify_accept_result'i  EOL @{
			type = NotifyAcceptResult;
		};
}%%

%% write data;

int NotifyAcceptResultParser::parse( const char *msg, long mLen )
{
	long cs;

	type = Unknown;
	%% write init;

	const char *p = msg;
	const char *pe = msg + strlen( msg );

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	return 0;
}


/*
 * prefriend_message_parser
 */

%%{
	machine prefriend_message_parser;

	include common;

	main :=
		'notify_accept'i ' ' requested_relid ' ' returned_relid EOL @{
			type = NotifyAccept;
		} |
		'registered'i ' ' requested_relid ' ' returned_relid EOL @{
			type = Registered;
		};

}%%

%% write data;

int PrefriendParser::parse( const char *msg, long mLen )
{
	/* Did we get a full line? */
	message("prefriend message: %.*s", (int)mLen, msg );

	long cs;
	const char *mark;

	type = Unknown;
	%% write init;

	const char *p = msg;
	const char *pe = msg + mLen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	return 0;
}

/*
 * message_parser
 */

%%{
	machine message_parser;

	include common;

	main := (
		'broadcast_key'i ' ' dist_name ' ' generation ' ' key
			EOL @{
				type = BroadcastKey;
			} |
		'encrypt_remote_broadcast'i ' ' token ' ' seq_num ' ' network ' ' length 
			EOL @skip_message EOL @{
				type = EncryptRemoteBroadcast;
			} |
		'return_remote_broadcast'i ' ' reqid ' ' generation ' ' sym
			EOL @{
				type = ReturnRemoteBroadcast;
			} |
		'friend_proof'i ' ' hash ' ' network ' ' generation ' ' sym
			EOL @{
				type = FriendProof;
			} |
		'user_message'i ' ' date ' ' length 
			EOL @skip_message EOL @{
				type = UserMessage;
			}
	)*;
}%%

%% write data;

int MessageParser::parse( const char *msg, long mLen )
{
	message("friend message: %.*s", (int)mLen, msg );

	long cs;
	const char *mark;
	String gen_str, seq_str, length_str;

	%% write init;

	const char *p = msg;
	const char *pe = msg + mLen;
	type = Unknown;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	return 0;
}

/*
 * broadcast_parser
 */

%%{
	machine broadcast_parser;

	include common;

	main :=
		'direct_broadcast'i ' ' seq_num ' ' date ' ' length 
			EOL @skip_message EOL @{
				type = Direct;
			} |
		'remote_broadcast'i ' ' hash ' ' network ' ' generation ' ' seq_num ' ' length 
			EOL @skip_message EOL @{
				type = Remote;
			} |
		'group_member_revocation'i ' ' network ' ' generation ' ' identity
			EOL @{
				type = GroupMemberRevocation;
			};
}%%

%% write data;

int BroadcastParser::parse( const char *msg, long mLen )
{
	message("broadcast message: %.*s", (int)mLen, msg );

	long cs;
	const char *mark;
	String length_str;
	String seq_str, gen_str;

	type = Unknown;
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
 * remote_broadcast_parser
 */

%%{
	machine remote_broadcast_parser;

	include common;

	main :=
		'remote_inner'i ' ' seq_num ' ' date ' ' length 
			EOL @skip_message EOL @{
				type = RemoteInner;
			} |
		'friend_proof'i ' ' identity1 ' ' identity2 ' ' date 
			EOL @{
				type = FriendProof;
			};

}%%

%% write data;

int RemoteBroadcastParser::parse( const char *msg, long mLen )
{
	long cs;
	const char *mark;
	String length_str, seq_str;

	type = Unknown;
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
 * encrypted_broadcast_parser
 */

%%{
	machine encrypted_broadcast_parser;

	include common;

	main :=
		'encrypted_broadcast' ' ' generation ' ' sym EOL @{
		};
}%%

%% write data;

long EncryptedBroadcastParser::parse( const char *msg )
{
	long cs;
	const char *mark;
	String gen_str;

	type = Unknown;
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
 * fetchPublicKeyNet
 */

%%{
	machine public_key;
	write data;
}%%

void fetchPublicKeyNet( PublicKey &pub, const char *site, 
		const char *host, const char *user )
{
	static char buf[8192];
	long cs;
	const char *p, *pe;
	bool OK = false;
	const char *mark;
	String n, e;

	TlsConnect tlsConnect;
	tlsConnect.connect( host, site );

	BIO_printf( tlsConnect.sbio, "public_key %s\r\n", user );
	(void)BIO_flush( tlsConnect.sbio );

	/* Read the result. */
	int readRes = BIO_gets( tlsConnect.sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		throw ReadError();

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
		throw ParseError();
	
	if ( ! OK )
		throw ResponseIsError();
	
	pub.n = n.relinquish();
	pub.e = e.relinquish();
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
	tlsConnect.connect( host, site );

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, "fetch_requested_relid %s\r\n", fr_reqid );
	(void)BIO_flush( tlsConnect.sbio );

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
	tlsConnect.connect( host, site );

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, "fetch_response_relid %s\r\n", reqid );
	(void)BIO_flush( tlsConnect.sbio );

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
	tlsConnect.connect( host, site );

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, "fetch_ftoken %s\r\n", flogin_reqid );
	(void)BIO_flush( tlsConnect.sbio );

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
 * IdentityOrig::parse()
 */

%%{
	machine identity_orig;
	write data;
}%%

long IdentityOrig::parse()
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
	
	host = allocString( h1, h2 );
	user = allocString( pp1, pp2 );

	/* We can use the start of the last path part to get the site. */
	site = allocString( identity, pp1 );

	return result;
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
	const char *p = iduri;
	const char *pe = p + strlen(iduri);
	const char *eof = pe;

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


	long result = 0, cs;

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return ERR_PARSE_ERROR;
	
	_host.set( h1, h2 );
	_user.set( pp1, pp2 );

	/* We can use the start of the last path part to get the site. */
	_site.set( iduri, pp1 );
	parsed = true;
	return result;
}

/*
 * send_broadcast_net
 */

%%{
	machine send_broadcast_net;
	write data;
}%%

long sendBroadcastNet( MYSQL *mysql, const char *toSite, RecipientList &recipients,
		const char *network, long long keyGen, const char *msg, long mLen )
{
	static char buf[8192];
	long cs;
	const char *p, *pe;
	bool OK = false;
	long pres;
	String relid, gen_str, seq_str;

	/* Need to parse the identity. */
	IdentityOrig site( toSite );
	pres = site.parse();

	if ( pres < 0 )
		return pres;

	TlsConnect tlsConnect;
	tlsConnect.connect( site.host, toSite );
	
	for ( RecipientList::iterator r = recipients.begin(); r != recipients.end(); r++ ) {
		BIO_printf( tlsConnect.sbio, 
			"broadcast_recipient %s\r\n", r->c_str() );
		(void)BIO_flush( tlsConnect.sbio );

		/* Read the result. */
		BIO_gets( tlsConnect.sbio, buf, 8192 );
	}

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, "broadcast %s %lld %ld\r\n", 
			network, keyGen, mLen );
	BIO_write( tlsConnect.sbio, msg, mLen );
	BIO_write( tlsConnect.sbio, "\r\n", 2 );
	(void)BIO_flush( tlsConnect.sbio );

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

long sendMessageNet( MYSQL *mysql, bool prefriend, const char *from_user,
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
	IdentityOrig toIdent( to_identity );
	pres = toIdent.parse();

	if ( pres < 0 )
		return pres;

	TlsConnect tlsConnect;
	tlsConnect.connect( toIdent.host, toIdent.site );

	/* Send the request. */
	BIO_printf( tlsConnect.sbio, "%smessage %s %ld\r\n", prefriend ? "prefriend_" : "", relid, mLen );
	BIO_write( tlsConnect.sbio, message, mLen );
	BIO_write( tlsConnect.sbio, "\r\n", 2 );
	(void)BIO_flush( tlsConnect.sbio );

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

			if ( result_message != 0 ) 
				*result_message = decrypt_result( mysql, from_user, to_identity, user_message );

			OK = true;
		}

		action token {
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
