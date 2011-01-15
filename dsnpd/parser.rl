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

#include "dsnp.h"
#include "string.h"
#include "error.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_MSG_LEN 16384

#include <unistd.h>
#include <fcntl.h>


bool gblKeySubmitted = false;

/* FIXME: check all scanned lengths for overflow. */

%%{
	machine common;

	action clear { buf.clear(); }
	action buf { buf.append( fc ); }

	base64 = [A-Za-z0-9\-_]+;
	user = [a-zA-Z0-9_.]+       >clear $buf %{ user.set(buf); };
	pass = graph+               >clear $buf %{ pass.set(buf); };
	reqid = base64              >clear $buf %{ reqid.set(buf); };
	hash = base64               >clear $buf %{ hash.set(buf); };
	key = base64                >clear $buf %{ key.set(buf); };
	sym = base64                >clear $buf %{ sym.set(buf); };
	sym1 = base64               >clear $buf %{ sym1.set(buf); };
	sym2 = base64               >clear $buf %{ sym2.set(buf); };
	relid = base64              >clear $buf %{ relid.set(buf); };
	token = base64              >clear $buf %{ token.set(buf); };
	id_salt = base64            >clear $buf %{ id_salt.set(buf); };
	requested_relid = base64    >clear $buf %{ requestedRelid.set(buf); };
	returned_relid = base64     >clear $buf %{ returnedRelid.set(buf); };
	dist_name = base64          >clear $buf %{ distName.set(buf); };

	n = base64                  >clear $buf %{ n.set(buf); };
	e = base64                  >clear $buf %{ e.set(buf); };

	date = ( 
		digit{4} '-' digit{2} '-' digit{2} ' ' 
		digit{2} ':' digit{2} ':' digit{2} 
	)
	>clear $buf %{date.set(buf);};

	path_part = (graph-'/')+;

	identity_pat = 
		( 'https://' path_part '/' ( path_part '/' )* );

	identity  = identity_pat >clear $buf %{ identity.set(buf); };
	identity1 = identity_pat >clear $buf %{ identity1.set(buf); };
	identity2 = identity_pat >clear $buf %{ identity2.set(buf); };

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

	length = [0-9]+           
		>clear $buf
		%{
			/* Note we must set counter here as well. All lengths are followed
			 * by some block of input. */
			buf.append( 0 );
			length = counter = parseLength( buf.data );
		};

	seq_num = [0-9]+          
		>clear $buf
		%{
			buf.append( 0 );
			seqNum = parseId( buf.data );
		};

	EOL = '\r'? '\n';

	# Count down the length. Assumed to have counter set.
	action dec { counter-- }
	nbytes = ( any when dec )* %when !dec;

	action collect_message {
		body.set( buf );
	}
	
	# Must be preceded by use of a 'length' machine.
	M_EOL =
		EOL nbytes >clear $buf %collect_message EOL;
}%%

/*
 * Identity::parse()
 */

%%{
	machine identity;
	write data;
}%%

long Identity::parse()
{
	const char *p = iduri.data;
	const char *pe = p + iduri.length;
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
		throw ParseError();
	
	_host.set( h1, h2 );
	_user.set( pp1, pp2 );

	/* We can use the start of the last path part to get the site. */
	_site.set( iduri, pp1 );
	parsed = true;
	return result;
}

/*
 * Server Loop
 */

%%{
	machine server_loop;

	include common;

	action check_key {
		if ( !gblKeySubmitted )
			fgoto *server_loop_error;
	}

	action check_tls {
		if ( !tls ) {
			message("tls check failed\n");
			fgoto *server_loop_error;
		}
	}

	commands := (
#		'comm_key'i ' ' key
#			EOL @{
#				message( "command: comm_key %s\n", key() );
#				/* Check the authentication. */
#				if ( strcmp( key, c->CFG_COMM_KEY ) == 0 ) {
#					gblKeySubmitted = true;
#					server->bioWrap->printf( "OK\r\n" );
#				}
#				else
#					fgoto *server_loop_error;
#			} |
#
#		'start_tls'i 
#			EOL @{
#				message( "command: start_tls\n" );
#				server->bioWrap->rbio = server->bioWrap->wbio = 
#					startTls( server->bioWrap->rbio, server->bioWrap->wbio );
#
#				tls = true;
#			} |

		'login'i ' ' user ' ' pass 
			EOL @check_key @{
				message( "command: login %s <pass>\n", user() );
				server->login( user, pass );
			} |

		# Admin commands.
		'new_user'i ' ' user ' ' pass
			EOL @check_key @{
				message( "command: new_user %s %s\n", user(), pass() );
				server->newUser( user, pass );
			} |

		# Public key sharing.
		'public_key'i ' ' user
			EOL @check_tls @{
				message( "command: public_key %s\n", user() );
				server->publicKey( user );
			} |

		# 
		# Friend Request.
		#
		'relid_request'i ' ' user ' ' identity
			EOL @check_key @{
				message( "command: relid_request %s %s\n", user(), identity() );
				server->relidRequest( user, identity );
			} |

		'relid_response'i ' ' user ' ' reqid ' ' identity
			EOL @check_key @{
				message( "command: relid_response %s %s %s\n", user(), reqid(), identity() );
				server->relidResponse( user, reqid, identity );
			} |

		'friend_final'i ' ' user ' ' reqid ' ' identity
			EOL @check_key @{
				message( "command: friend_final %s %s %s\n", user(), reqid(), identity() );
				server->friendFinal( user, reqid, identity );
			} |

		'fetch_requested_relid'i ' ' reqid
			EOL @check_tls @{
				message( "command: fetch_requested_relid %s\n", reqid() );
				server->fetchRequestedRelid( reqid );
			} |

		'fetch_response_relid'i ' ' reqid
			EOL @check_tls @{
				message( "command: fetch_response_relid %s\n", reqid() ) ;
				server->fetchResponseRelid( reqid );
			} |

		#
		# Friend Request Accept
		#
		'accept_friend'i ' ' user ' ' reqid
			EOL @check_key @{
				message( "command: accept_friend %s %s\n", user(), reqid() );
				server->acceptFriend( user, reqid );
			} |

		'prefriend_message'i ' ' relid ' ' length 
			M_EOL @check_tls @{
				message( "command: prefriend_mesage %s %ld\n", relid(), length );
				server->prefriendMessage( relid, body );
			} |

		#
		# Friend login. 
		#
		'ftoken_request'i ' ' user ' ' hash
			EOL @check_key @{
				message( "command: ftoken_request %s %s\n", user(), hash() );
				server->ftokenRequest( user, hash );
			} |

		'ftoken_response'i ' ' user ' ' hash ' ' reqid
			EOL @check_key @{
				message( "command: ftoken_response %s %s %s\n", user(), hash(), reqid() );
				server->ftokenResponse( user, hash, reqid );
			} |

		'fetch_ftoken'i ' ' reqid
			EOL @check_tls @{
				message( "command: fetch_ftoken %s\n", reqid() );
				server->fetchFtoken( reqid );
			} |

		'submit_ftoken'i ' ' token
			EOL @check_key @{
				message( "command: submit_ftoken %s\n", token() );
				server->submitFtoken( token );
			} |

		#
		# Direct messages to friends
		#

		# Not currently used?
		'submit_message'i ' ' user ' ' identity ' ' length
			M_EOL @check_key @{
				message( "command: submit_message %s %s %ld\n", user(), identity(), length );
				server->submitMessage( user, identity, body, length );
			} |

		#
		# Broadcasting
		#
		'submit_broadcast'i ' ' user ' ' length 
			M_EOL @check_key @{
				message( "command: submit_broadcast %s %ld\n", user(), length );
				server->submitBroadcast( user, body, length );
			} |

		#
		# Remote broadcasting
		#
		'remote_broadcast_request'i ' ' user ' ' identity ' ' hash ' ' token ' ' length
			M_EOL @check_key @{
				message( "command: remote_broadcast_request %s %s %s %s %ld\n",
						user(), identity(), hash(), token(), length );
				server->remoteBroadcastRequest( user, identity, hash, 
						token, body, length );
			} |

		'remote_broadcast_response'i ' ' user ' ' reqid
			EOL @check_key @{
				message( "command: remote_broadcast_response %s %s\n", user(), reqid() );
				server->remoteBroadcastResponse( user, reqid );
			} |

		'remote_broadcast_final'i ' ' user ' ' reqid
			EOL @check_key @{
				message( "command: remote_broadcast_final %s %s\n", user(), reqid() );
				server->remoteBroadcastFinal( user, reqid );
			} |

		#
		# Message sending.
		#
		'message'i ' ' relid ' ' length 
			M_EOL @check_tls @{
				message( "command: message %s %ld\n", relid(), length );
				server->receiveMessage( relid, body );
			} |

		'broadcast_recipient'i ' ' relid
			EOL @check_tls @{
				message( "command: broadcast_recipient %s\n", relid() );
				server->broadcastReceipient( recipients, relid );
			} |

		'broadcast'i ' ' dist_name ' ' generation ' ' length
			M_EOL @check_tls @{
				message( "command: broadcast %s %lld %ld\n", distName(), generation, length );
				server->receiveBroadcast( recipients, distName, generation, body );
				recipients.clear();
			}
	)*;

	#
	# Suppored Versions
	#
	version_0_1 = 
		'0.1' %{
			v = VERSION_MASK_0_1;
		};

	version = ( version_0_1 )
		%{
			if ( versions & v )
				throw VersionAlreadyGiven();

			versions |= v;
		};

	supported_versions =  version ( '|' version )*;

	#
	# Site selection, can use the identity defintiion for this. 
	#
	site = identity;

	#
	# Authentication methods, rely on SSL, or accept a key on a local
	# connection. 
	#
	auth = ( 
		'start_tls'i @{ tls = true; } | 
		'local'i ' ' key
	);

	main := 
		'DSNP ' supported_versions ' ' site ' ' auth
			EOL @{
				server->negotiation( versions, identity, tls, key );
				fgoto commands;
			};
}%%

%% write data;

ServerParser::ServerParser()
:
	retVal(0),
	mysql(0),
	tls(false),
	exit(false),
	versions(0)
{

	%% write init;
}

Parser::Control ServerParser::data( const char *data, int dlen )
{
	const char *p = data;
	const char *pe = data + dlen;

	%% write exec;

	if ( exit && cs >= %%{ write first_final; }%% )
		return Stop;

	/* Did parsing succeed? */
	if ( cs == %%{ write error; }%% )
		throw ParseError();

	return Continue;
}

void serverParseLoop( BIO *rbio, BIO *wbio )
{
	BioWrap bioWrap;
	bioWrap.rbio = rbio;
	bioWrap.wbio = wbio;

	Server server;
	server.bioWrap = &bioWrap;

	ServerParser parser;
	parser.server = &server;

	bioWrap.readParse( parser );
}

/*
 * prefriend_message_parser
 */

%%{
	machine prefriend_message_parser;

	include common;

	main :=
		'notify_accept'i ' ' requested_relid ' ' returned_relid EOL @{
			message("prefriend_message: notify_accept %s %s\n",
					requestedRelid(), returnedRelid() );
			type = NotifyAccept;
		} |
		'registered'i ' ' requested_relid ' ' returned_relid EOL @{
			message("prefriend_message: registered %s %s\n",
					requestedRelid(), returnedRelid() );
			type = Registered;
		};

}%%

%% write data;

Parser::Control PrefriendParser::data( const char *data, int dlen )
{
	long cs;
	Buffer buf;

	type = Unknown;
	%% write init;

	const char *p = data;
	const char *pe = data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	return Continue;
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
				message( "message: broadcast_key %s %lld %s\n", distName(), generation, key() );
				type = BroadcastKey;
			} |
		'encrypt_remote_broadcast'i ' ' token ' ' seq_num ' ' length 
			M_EOL @{
				message( "message: encrypt_remote_broadcast %s %lld %ld\n", token(), seqNum, length );
				type = EncryptRemoteBroadcast;
			} |
		'return_remote_broadcast'i ' ' reqid ' ' dist_name ' ' generation ' ' sym
			EOL @{
				message( "message: return_remote_broadcast %s %s %ld %s\n",
						reqid(), distName(), generation, sym() );
				type = ReturnRemoteBroadcast;
			} |
		'user_message'i ' ' date ' ' length 
			M_EOL @{
				message( "message: user_message\n" );
				type = UserMessage;
			}
	)*;
}%%

%% write data;

Parser::Control MessageParser::data( const char *data, int dlen )
{
	long cs;
	Buffer buf;

	%% write init;

	const char *p = data;
	const char *pe = data + dlen;
	type = Unknown;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	return Continue;
}

/*
 * broadcast_parser
 */

%%{
	machine broadcast_parser;

	include common;

	main :=
		'direct_broadcast'i ' ' seq_num ' ' date ' ' length 
			M_EOL @{
				message("broadcast: direct_broadcast %lld %s %ld\n", seqNum, date(), length );
				type = Direct;
			} |
		'remote_broadcast'i ' ' hash ' ' dist_name ' ' generation ' ' seq_num ' ' length 
			M_EOL @{
				message("broadcast: remote_broadcast %s %s %lld %ld %lld\n", 
						hash(), distName(), generation, seqNum, length );
				type = Remote;
			};
}%%

%% write data;

Parser::Control BroadcastParser::data( const char *data, int dLen )
{
	long cs;
	Buffer buf;

	type = Unknown;
	%% write init;

	const char *p = data;
	const char *pe = data + dLen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	return Continue;
}

/*
 * remote_broadcast_parser
 */

%%{
	machine remote_broadcast_parser;

	include common;

	main :=
		'remote_inner'i ' ' seq_num ' ' date ' ' length 
			M_EOL @{
				message("remote_broadcast: remote_inner %lld %s %ld\n", seqNum, date(), length );
				type = RemoteInner;
			};
}%%

%% write data;

Parser::Control RemoteBroadcastParser::data( const char *data, int dLen )
{
	long cs;
	Buffer buf;

	type = Unknown;
	%% write init;

	const char *p = data;
	const char *pe = data + dLen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	return Continue;
}

/*
 * fetchPublicKeyNet
 */

%%{
	machine public_key;
	write data;
}%%

FetchPublicKeyParser::FetchPublicKeyParser()
{
	OK = false;
	%% write init;
}

Parser::Control FetchPublicKeyParser::data( const char *data, int dlen )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' n ' ' e EOL @{ OK = true; fbreak; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + dlen;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs == %%{ write error; }%% )
		throw ParseError();

	if ( cs >= %%{ write first_final; }%% )
		return Stop;

	return Continue;
}

void fetchPublicKeyNet( PublicKey &pub, const char *site, 
		const char *host, const char *user )
{
	TlsConnect tlsConnect;
	FetchPublicKeyParser parser;

	/* Connect and send the public key request. */
	tlsConnect.connect( host, site );
	tlsConnect.printf( "public_key %s\r\n", user );

	/* Parse the result. */
	tlsConnect.readParse( parser );

	/* Result. */
	pub.n = parser.n.relinquish();
	pub.e = parser.e.relinquish();
}

/*
 * fetchRequestedRelidNet
 */

%%{
	machine fr_relid;
	write data;
}%%

FetchRequestedRelidParser::FetchRequestedRelidParser()
{
	OK = false;
	%% write init;
}

Parser::Control FetchRequestedRelidParser::data( const char *data, int dlen )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' sym EOL @{ OK = true; fbreak; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + dlen;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	if ( cs >= %%{ write first_final; }%% )
		return Stop;

	return Continue;
}

void fetchRequestedRelidNet( RelidEncSig &encsig, const char *site, 
		const char *host, const char *fr_reqid )
{
	TlsConnect tlsConnect;
	FetchRequestedRelidParser parser;

	tlsConnect.connect( host, site );

	/* Send the request. */
	tlsConnect.printf( "fetch_requested_relid %s\r\n", fr_reqid );

	/* Parse the result. */
	tlsConnect.readParse( parser );

	/* Output. */
	encsig.sym = parser.sym.relinquish();
}

/*
 * fetchResponseRelidNet
 */

%%{
	machine relid;
	write data;
}%%

FetchResponseRelidParser::FetchResponseRelidParser()
{
	OK = false;
	%% write init;
}

Parser::Control FetchResponseRelidParser::data( const char *data, int dlen )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' sym EOL @{ OK = true; fbreak; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + dlen;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	if ( cs >= %%{ write first_final; }%% )
		return Stop;

	return Continue;
}

void fetchResponseRelidNet( RelidEncSig &encsig, const char *site,
		const char *host, const char *reqid )
{
	TlsConnect tlsConnect;
	FetchResponseRelidParser parser;

	tlsConnect.connect( host, site );

	/* Send the request. */
	tlsConnect.printf( "fetch_response_relid %s\r\n", reqid );

	/* Parse the result. */
	tlsConnect.readParse( parser );

	/* Output. */
	encsig.sym = parser.sym.relinquish();
}

/*
 * fetchFtokenNet
 */

%%{
	machine ftoken;
	write data;
}%%

FetchFtokenParser::FetchFtokenParser()
{
	OK = false;
	%% write init;
}

Parser::Control FetchFtokenParser::data( const char *data, int dlen )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' sym EOL @{ OK = true; fbreak; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + dlen;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	if ( cs >= %%{ write first_final; }%% )
		return Stop;

	return Continue;
}

void fetchFtokenNet( RelidEncSig &encsig, const char *site,
		const char *host, const char *flogin_reqid )
{
	TlsConnect tlsConnect;
	FetchResponseRelidParser parser;

	tlsConnect.connect( host, site );

	/* Send the request. */
	tlsConnect.printf( "fetch_ftoken %s\r\n", flogin_reqid );

	/* Parse the result. */
	tlsConnect.readParse( parser );

	/* Output. */
	encsig.sym = parser.sym.relinquish();
}

/*
 * send_broadcast_net
 */

%%{
	machine send_broadcast_recipient_net;
	write data;
}%%

SendBroadcastRecipientParser::SendBroadcastRecipientParser()
{
	OK = false;
	%% write init;
}

Parser::Control SendBroadcastRecipientParser::data( const char *data, int dlen )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK' EOL @{ OK = true; fbreak; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + dlen;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	if ( cs >= %%{ write first_final; }%% )
		return Stop;

	return Continue;
}

%%{
	machine send_broadcast_net;
	write data;
}%%

SendBroadcastParser::SendBroadcastParser()
{
	OK = false;
	%% write init;
}

Parser::Control SendBroadcastParser::data( const char *data, int dlen )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK' EOL @{ OK = true; fbreak; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + dlen;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	if ( cs >= %%{ write first_final; }%% )
		return Stop;

	return Continue;
}

long sendBroadcastNet( MYSQL *mysql, const char *toHost,
		const char *toSite, RecipientList &recipients,
		const char *network, long long keyGen, const char *msg, long mLen )
{
	TlsConnect tlsConnect;
	tlsConnect.connect( toHost, toSite );
	
	for ( RecipientList::iterator r = recipients.begin(); r != recipients.end(); r++ ) {
		/* FIXME: catch errors here. */
		tlsConnect.printf( 
			"broadcast_recipient %s\r\n", r->c_str() );

		SendBroadcastRecipientParser parser;
		tlsConnect.readParse( parser );
	}

	/* Send the request. */
	tlsConnect.printf( "broadcast %s %lld %ld\r\n", network, keyGen, mLen );
	tlsConnect.write( msg, mLen );
	tlsConnect.closeMessage();

	SendBroadcastParser parser;
	tlsConnect.readParse( parser );

	return 0;
}

/*
 * send_message_net
 */

%%{
	machine send_message_net;
	write data;
}%%

SendMessageParser::SendMessageParser()
{
	OK = false;
	hasToken = false;
	%% write init;
}

Parser::Control SendMessageParser::data( const char *data, int dlen )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK' EOL @{ 
				OK = true; 
				fbreak;
			} |
			'OK' ' ' token EOL @{ 
				OK = true;
				hasToken = true;
				fbreak;
			} |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + dlen;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();

	if ( cs >= %%{ write first_final; }%% )
		return Stop;

	return Continue;
}

void sendMessageNet( MYSQL *mysql, bool prefriend, const char *user,
		const char *identity, const char *relid, const char *msg,
		long mLen, String &result )
{
	/* Need to parse the identity. */
	Identity toIdent( mysql, identity );

	TlsConnect tlsConnect;
	SendMessageParser parser;

	tlsConnect.connect( toIdent.host(), toIdent.site() );

	/* Send the request. */
	tlsConnect.printf("%smessage %s %ld\r\n",
			prefriend ? "prefriend_" : "", relid, mLen );
	tlsConnect.write( msg, mLen );
	tlsConnect.closeMessage();

	tlsConnect.readParse( parser );

	if ( parser.hasToken )
		result.set( parser.token );
}
