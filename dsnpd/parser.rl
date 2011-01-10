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
	network = [a-zA-Z0-9_.\-]+  >clear $buf %{ network.set(buf); };
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

	identity  = identity_pat >clear $buf %{identity.set(buf);};
	identity1 = identity_pat >clear $buf %{identity1.set(buf);};
	identity2 = identity_pat >clear $buf %{identity2.set(buf);};

	generation = [0-9]+       
		>clear $buf
		%{
			gen_str.set(buf);
			generation = strtoll( gen_str, 0, 10 );
		};

	number = [0-9]+           
		>clear $buf
		%{
			number_str.set(buf);
			number = strtol( number_str, 0, 10 );
		};

	length = [0-9]+           
		>clear $buf
		%{
			length_str.set(buf);
			length = counter = strtol( length_str, 0, 10 );
			//message("length: %ld\n", length );
		};

	seq_num = [0-9]+          
		>clear $buf
		%{
			seq_str.set(buf);
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

	action dec { counter-- }

	nbytes = ( any when dec )* %when !dec;

	action collect_message {
		messageBody.set( buf );
	}
	
	M_EOL =
		EOL nbytes >clear $buf %collect_message EOL;
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

	commands := (
		'comm_key'i ' ' key
			EOL @{
				/* Check the authentication. */
				if ( strcmp( key, c->CFG_COMM_KEY ) == 0 )
					gblKeySubmitted = true;
				else
					fgoto *parser_error;
			} |

		'start_tls'i 
			EOL @{
				startTls();
				ssl = true;
			} |

		'login'i ' ' user ' ' pass 
			EOL @check_key @{
				message( "command: login %s %s\n", user(), pass() );
				login( mysql, user, pass );
			} |

		# Admin commands.
		'new_user'i ' ' user ' ' pass
			EOL @check_key @{
				message( "command: new_user %s %s\n", user(), pass() );
				newUser( mysql, user, pass );
			} |

		# Public key sharing.
		'public_key'i ' ' user
			EOL @check_ssl @{
				message( "command: public_key %s\n", user() );
				publicKey( mysql, user );
			} |

		# 
		# Friend Request.
		#
		'relid_request'i ' ' user ' ' identity
			EOL @check_key @{
				message( "command: relid_request %s %s\n", user(), identity() );
				relidRequest( mysql, user, identity );
			} |

		'relid_response'i ' ' user ' ' reqid ' ' identity
			EOL @check_key @{
				message( "command: relid_response %s %s %s\n", user(), reqid(), identity() );
				relidResponse( mysql, user, reqid, identity );
			} |

		'friend_final'i ' ' user ' ' reqid ' ' identity
			EOL @check_key @{
				message( "command: friend_final %s %s %s\n", user(), reqid(), identity() );
				friendFinal( mysql, user, reqid, identity );
			} |

		'fetch_requested_relid'i ' ' reqid
			EOL @check_ssl @{
				message( "command: fetch_requested_relid %s\n", reqid() );
				fetchRequestedRelid( mysql, reqid );
			} |

		'fetch_response_relid'i ' ' reqid
			EOL @check_ssl @{
				message( "command: fetch_response_relid %s\n", reqid() ) ;
				fetchResponseRelid( mysql, reqid );
			} |

		#
		# Friend Request Accept
		#
		'accept_friend'i ' ' user ' ' reqid
			EOL @check_key @{
				message( "command: accept_friend %s %s\n", user(), reqid() );
				acceptFriend( mysql, user, reqid );
			} |

		'prefriend_message'i ' ' relid ' ' length 
			M_EOL @check_ssl @{
				message( "command: prefriend_mesage %s %lld\n", relid(), length );
				prefriendMessage( mysql, relid, messageBody.data );
			} |

		#
		# Friend login. 
		#
		'ftoken_request'i ' ' user ' ' hash
			EOL @check_key @{
				message( "command: ftoken_request %s %s\n", user(), hash() );
				ftokenRequest( mysql, user, hash );
			} |

		'ftoken_response'i ' ' user ' ' hash ' ' reqid
			EOL @check_key @{
				message( "command: ftoken_response %s %s %s\n", user(), hash(), reqid() );
				ftokenResponse( mysql, user, hash, reqid );
			} |

		'fetch_ftoken'i ' ' reqid
			EOL @check_ssl @{
				message( "command: fetch_ftoken %s\n", reqid() );
				fetchFtoken( mysql, reqid );
			} |

		'submit_ftoken'i ' ' token
			EOL @check_key @{
				message( "command: submit_ftoken %s\n", token() );
				submitFtoken( mysql, token );
			} |

		#
		# Broadcasting
		#
		'submit_broadcast'i ' ' user ' ' length 
			M_EOL @check_key @{
				message( "command: submit_broadcast %lld\n", length );
				submitBroadcast( mysql, user, messageBody.data, length );
			} |

		#
		# Direct messages to friends
		#
		'submit_message'i ' ' user ' ' identity ' ' length
			M_EOL @check_key @{
				message( "command: submit_message %s %s %lld\n", user(), identity(), length );
				submitMessage( mysql, user, identity, messageBody.data, length );
			} |

		#
		# Remote broadcasting
		#
		'remote_broadcast_request'i ' ' user ' ' identity ' ' hash ' ' token ' ' length
			M_EOL @check_key @{
				message( "command: remote_broadcast_request %s %s %s %s %lld\n",
						user(), identity(), hash(), token(), length );
				remoteBroadcastRequest( mysql, user, identity, hash, 
						token, messageBody.data, length );
			} |

		'remote_broadcast_response'i ' ' user ' ' reqid
			EOL @check_key @{
				message( "command: remote_broadcast_response %s %s\n", user(), reqid() );
				remoteBroadcastResponse( mysql, user, reqid );
			} |

		'remote_broadcast_final'i ' ' user ' ' reqid
			EOL @check_key @{
				message( "command: remote_broadcast_final %s %s\n", user(), reqid() );
				remoteBroadcastFinal( mysql, user, reqid );
			} |

		#
		# Message sending.
		#
		'message'i ' ' relid ' ' length 
			M_EOL @check_ssl @{
				message( "command: message %s %lld\n", relid(), length );
				receiveMessage( mysql, relid, messageBody.data );
			} |

		'broadcast_recipient'i ' ' relid
			EOL @{
				message( "command: broadcast_recipient %s\n", relid() );
				broadcastReceipient( mysql, recipients, relid );
			} |

		'broadcast'i ' ' network ' ' generation ' ' length
			M_EOL @check_ssl @{
				message( "command: broadcast %s %lld %ld\n", network(), generation, length );
				receiveBroadcast( mysql, recipients, network, generation, messageBody.data );
				recipients.clear();
			}
	)*;

	main := 'DSNP/0.1'i ' ' identity %set_config EOL @{ fgoto commands; };
}%%

%% write data;

ServerParser::ServerParser()
{
	retVal = 0;
	mysql = 0;
	ssl = false;
	exit = false;

	%% write init;
}

void ServerParser::data( char *data, int len )
{
	const char *p = data;
	const char *pe = data + len;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs == %%{ write error; }%% )
		throw ParseError();
}

int serverParseLoop()
{
	BioSocket bioSocket;
	bioSocket.sbio = bioIn;

	ServerParser parser;

	bioSocket.readParse2( parser );

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
	Buffer buf;

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
		'encrypt_remote_broadcast'i ' ' token ' ' seq_num ' ' length 
			EOL @skip_message EOL @{
				type = EncryptRemoteBroadcast;
			} |
		'return_remote_broadcast'i ' ' reqid ' ' network ' ' generation ' ' sym
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
	Buffer buf;
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
	Buffer buf;
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
	Buffer buf;
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
	Buffer buf;
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

FetchPublicKeyParser::FetchPublicKeyParser()
{
	OK = false;
	%% write init;
}

void FetchPublicKeyParser::data( char *data, int len )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' n ' ' e EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + len;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs == %%{ write error; }%% )
		throw ParseError();
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

void FetchRequestedRelidParser::data( char *data, int len )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' sym EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + len;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();
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

void FetchResponseRelidParser::data( char *data, int len )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' sym EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + len;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();
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

void FetchFtokenParser::data( char *data, int len )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK ' sym EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + len;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();
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
	machine send_broadcast_recipient_net;
	write data;
}%%

SendBroadcastRecipientParser::SendBroadcastRecipientParser()
{
	OK = false;
	%% write init;
}

void SendBroadcastRecipientParser::data( char *data, int len )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK' EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + len;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();
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

void SendBroadcastParser::data( char *data, int len )
{
	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK' EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + len;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();
}

long sendBroadcastNet( MYSQL *mysql, const char *toSite, RecipientList &recipients,
		const char *network, long long keyGen, const char *msg, long mLen )
{
	/* Need to parse the identity. */
	IdentityOrig site( toSite );
	long pres = site.parse();

	if ( pres < 0 )
		return pres;

	TlsConnect tlsConnect;
	tlsConnect.connect( site.host, toSite );
	
	for ( RecipientList::iterator r = recipients.begin(); r != recipients.end(); r++ ) {
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
	%% write init;
}

void SendMessageParser::data( char *data, int len )
{
	/* Parser for response. */
	%%{
		include common;

		action token {
			OK = true;
		}

		main := 
			'OK' EOL @{ OK = true; } |
			'REQID' ' ' token EOL @token |
			'ERROR' EOL;
	}%%

	const char *p = data;
	const char *pe = data + len;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError();
}

void sendMessageNet( MYSQL *mysql, bool prefriend, const char *user,
		const char *identity, const char *relid, const char *msg,
		long mLen, char **resultMessage )
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

	if ( resultMessage != 0 ) {
		*resultMessage = new char[parser.token.length+1];
		memcpy( *resultMessage, parser.token.data, parser.token.length );
		resultMessage[parser.token.length] = 0;
	}
}
