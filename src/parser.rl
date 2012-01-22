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
#include "encrypt.h"

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

/* FIXME: check all scanned lengths for overflow. */

/* Need this for the time being. */
u_char *writeExact( u_char *dest, const String &s )
{
	memcpy( dest, s(), s.length );
	dest += s.length;
	return dest;
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
	const u_char *p = (u_char*)iduri.data;
	const u_char *pe = p + iduri.length;

	const u_char *h1, *h2;

	/* Parser for response. */
	%%{
		include common "common.rl";

		main :=
			scheme '://' path_part >{h1=p;} %{h2=p;} '/' rel_path;
	}%%

	long result = 0, cs;

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );
	
	_host.set( (const char*)h1, (const char*)h2 );

	/* We can use the start of the last path part to get the site. */
	parsed = true;
	return result;
}

/*
 * Server Loop
 */


%%{
	machine server_loop;

	include common "common.rl";

	commands_local := (
		'login'i ' ' user ' ' pass ' ' session_id
			EOL @{
				message( "command: login %s <pass>\n", user() );
				server->login( user, pass, sessionId );
			} |

		# 
		# Friend Request.
		#
		'relid_request'i ' ' user ' ' iduri
			EOL @{
				message( "command: relid_request %s %s\n", user(), iduri() );
				server->relidRequest( user, iduri );
			} |

		# Must be logged in.
		'relid_response'i ' ' login_token ' ' reqid ' ' iduri
			EOL @{
				message( "command: relid_response %s %s %s\n", 
						loginToken(), reqid(), iduri() );
				server->relidResponse( loginToken, reqid, iduri );
			} |

		'friend_final'i ' ' user ' ' reqid ' ' iduri
			EOL @{
				message( "command: friend_final %s %s %s\n", user(), reqid(), iduri() );
				server->friendFinal( user, reqid, iduri );
			} |

		#
		# Friend Request Accept
		#
		'accept_friend'i ' ' login_token ' ' reqid
			EOL @{
				message( "command: accept_friend %s %s\n", loginToken(), reqid() );
				server->acceptFriend( loginToken, reqid );
			} |

		#
		# Friend login. 
		#
		'ftoken_request'i ' ' user ' ' hash
			EOL @{
				message( "command: ftoken_request %s %s\n", user(), hash() );
				server->ftokenRequest( user, hash );
			} |

		'ftoken_response'i ' ' login_token ' ' hash ' ' reqid
			EOL @{
				message( "command: ftoken_response %s %s %s\n", loginToken(), hash(), reqid() );
				server->ftokenResponse( loginToken, hash, reqid );
			} |

		'submit_ftoken'i ' ' token ' ' session_id
			EOL @{
				message( "command: submit_ftoken %s\n", token() );
				server->submitFtoken( token, sessionId );
			} |

		#
		# Direct messages to friends
		#

		# Not currently used. Should be for private messages?
		'submit_message'i ' ' login_token ' ' iduri ' ' length
			M_EOL @{
				message( "command: submit_message %s %s %ld\n", loginToken(), iduri(), length );
				server->submitMessage( loginToken, iduri, body );
			} |

		#
		# Broadcasting
		#
		'submit_broadcast'i ' ' login_token ' ' length 
			M_EOL @{
				message( "command: submit_broadcast %s %ld\n", loginToken(), length );
				server->submitBroadcast( loginToken, body );
			} |

		#
		# Remote broadcasting
		#
		'remote_broadcast_request'i ' ' flogin_token ' ' length
			M_EOL @{
				message( "command: remote_broadcast_request %s %ld\n",
						floginToken(), length );
				server->remoteBroadcastRequest( floginToken, body );
			} |

		'remote_broadcast_response'i ' ' login_token ' ' reqid
			EOL @{
				message( "command: remote_broadcast_response %s %s\n",
						loginToken(), reqid() );
				server->remoteBroadcastResponse( loginToken, reqid );
			} |

		'remote_broadcast_final'i ' ' flogin_token ' ' reqid
			EOL @{
				message( "command: remote_broadcast_final %s %s\n",
						floginToken(), reqid() );
				server->remoteBroadcastFinal( floginToken, reqid );
			}
	)*;
}%%

#define CMD_PUBLIC_KEY                 50
#define CMD_FETCH_REQUESTED_RELID      51
#define CMD_FETCH_RESPONSE_RELID       52
#define CMD_FETCH_FTOKEN               53
#define CMD_MESSAGE                    54
#define CMD_FOF_MESSAGE                55
#define CMD_BROADCAST_RECIPIENT        56
#define CMD_BROADCAST                  57

Allocated consPublicKey( const String &user )
{
	long length = 1 + 
			stringLength( user );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_PUBLIC_KEY );
	dest = writeString( dest, user );

	return packet.relinquish();
}

Allocated consFetchRequestedRelid( const String &reqid )
{
	long length = 1 + 
			stringLength( reqid );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_FETCH_REQUESTED_RELID );
	dest = writeString( dest, reqid );

	return packet.relinquish();
}

Allocated consFetchResponseRelid( const String &reqid )
{
	long length = 1 + 
			stringLength( reqid );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_FETCH_RESPONSE_RELID );
	dest = writeString( dest, reqid );

	return packet.relinquish();
}

Allocated consFetchFtoken( const String &reqid )
{
	long length = 1 + 
			stringLength( reqid );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_FETCH_FTOKEN );
	dest = writeString( dest, reqid );

	return packet.relinquish();
}

Allocated consMessage( const String &relid, const String &msg )
{
	long length = 1 +
			stringLength( relid ) +
			binLength( msg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_MESSAGE );
	dest = writeString( dest, relid );
	dest = writeBin( dest, msg );

	return packet.relinquish();
}

Allocated consFofMessage( const String &relid, const String &msg )
{
	long length = 1 + 
			stringLength( relid ) +
			binLength( msg );

	message( "CONSING relid: %s\n", relid() );
	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_FOF_MESSAGE );
	dest = writeString( dest, relid );
	dest = writeBin( dest, msg );

	return packet.relinquish();
}

Allocated consBroadcastRecipient( const String &relid )
{
	long length = 1 + 
			stringLength( relid );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_BROADCAST_RECIPIENT );
	dest = writeString( dest, relid );

	return packet.relinquish();
}

Allocated consBroadcast( const String &network, long long keyGen, 
		const String &msg )
{
	long length = 1 + 
			stringLength( network ) +
			sixtyFourBitLength() +
			binLength( msg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, CMD_BROADCAST );
	dest = writeString( dest, network );
	dest = write64Bit( dest, keyGen );
	dest = writeBin( dest, msg );

	return packet.relinquish();
}

%%{
	machine server_loop;

	public_key                   = 50;
	fetch_requested_relid        = 51;
	fetch_response_relid         = 52;
	fetch_ftoken                 = 53;
	message                      = 54;
	fof_message                  = 55;
	broadcast_recipient          = 56;
	broadcast                    = 57;

	commands_tls := (
		# Public key sharing.
		public_key user0
			@{
				message( "command: public_key %s\n", user() );
				server->publicKey( user );
			} |

		# 
		# Friend Request.
		#

		fetch_requested_relid reqid0
			@{
				message( "command: fetch_requested_relid %s\n", reqid() );
				server->fetchRequestedRelid( reqid );
			} |

		fetch_response_relid reqid0
			@{
				message( "command: fetch_response_relid %s\n", reqid() ) ;
				server->fetchResponseRelid( reqid );
			} |

		#
		# Friend login. 
		#

		fetch_ftoken reqid0
			@{
				message( "command: fetch_ftoken %s\n", reqid() );
				server->fetchFtoken( reqid );
			} |

		#
		# Message sending.
		#
		message relid0 body
			@{
				message( "command: message %s %ld\n", relid(), length );
				server->receiveMessage( relid, body );
			} |

		fof_message relid0 body
			@{
				message( "command: fof_message %s %ld\n", relid(), length );
				server->receiveFofMessage( relid, body );
			} |

		broadcast_recipient relid0
			@{
				message( "command: broadcast_recipient %s\n", relid() );
				server->broadcastReceipient( recipientList, relid );
			} |

		broadcast dist_name0 generation64 body
			@{
				message( "command: broadcast %s %lld %ld\n", distName(), generation, length );
				server->receiveBroadcastList( recipientList, distName, generation, body );
				recipientList.clear();
			}
	)*;

	supported_versions =  version ( '|' version )*;

	#
	# Authentication methods, rely on SSL, or accept a key on a local
	# connection. 
	#
	auth = ( 
		'start_tls'i ' ' host %{ tls = true; } | 
		'local'i ' ' key
	);

	main := 
		'DSNP ' supported_versions ' ' auth
			EOL @{
				server->negotiation( versions, tls, host, key );
				if ( !tls )
					fgoto commands_local;
				else
					fgoto commands_tls;
			};
}%%

%% write data;

ServerParser::ServerParser( Server *server )
:
	retVal(0),
	mysql(0),
	tls(false),
	exit(false),
	versions(0),
	server(server)
{

	%% write init;
}

Parser::Control ServerParser::data( const char *data, int dlen )
{
	const unsigned char *p = (u_char*)data;
	const unsigned char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( exit && cs >= %%{ write first_final; }%% )
		return Stop;

	/* Did parsing succeed? */
	if ( cs == %%{ write error; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * response_parser
 */

#define RET_OK0 30
#define RET_OK1 31

Allocated consRet0()
{
	long length = 1;

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, RET_OK0 );

	return packet.relinquish();
}

Allocated consRet1( const String &arg )
{
	long length = 1 + 
			binLength( arg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, RET_OK1 );
	dest = writeBin( dest, arg );

	return packet.relinquish();
}

%%{
	machine response_parser;
	include common "common.rl";

	ok0 = 30;
	ok1 = 31;

	main := 
		ok0 
		@{ 
			OK = true; 
			fbreak;
		} |
		ok1 bin16 @{ body.set( buf ); }
		@{
			OK = true;
			fbreak;
		};
}%%

%%write data;

ResponseParser::ResponseParser()
:
	OK(false)
{
	%% write init;
}

Parser::Control ResponseParser::data( const char *data, int dlen )
{

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	/* Did parsing succeed? */
	if ( cs == %%{ write error; }%% )
		throw ParseError( __FILE__, __LINE__ );

	if ( cs >= %%{ write first_final; }%% )
		return Stop;

	return Continue;
}

#define PREFRIEND_MESSAGE_NOTIFY_ACCEPT    1
#define PREFRIEND_MESSAGE_REGISTERED       2

Allocated consNotifyAccept( const String &peerNotifyReqid )
{
	long length = 1 +
			stringLength( peerNotifyReqid );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, PREFRIEND_MESSAGE_NOTIFY_ACCEPT );
	dest = writeString( dest, peerNotifyReqid );

	return packet.relinquish();
}

Allocated consRegistered( const String &peerNotifyReqid, const String &friendClaimSigKey )
{
	long length = 1 +
			stringLength( peerNotifyReqid ) +
			binLength( friendClaimSigKey );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, PREFRIEND_MESSAGE_REGISTERED );
	dest = writeString( dest, peerNotifyReqid );
	dest = writeBin( dest, friendClaimSigKey );

	return packet.relinquish();
}


/*
 * prefriend_message_parser
 */

%%{
	machine prefriend_message_parser;

	include common "common.rl";

	notify_accept   = 1;
	registered      = 2;

	peer_notify_reqid = 
		base64  >clear $buf 0 @{
			peerNotifyReqid.set(buf);
		};
	
	friend_claim_sig_key =
		bin16 @{
			friendClaimSigKey.set( buf );
		};
	
	main :=
		notify_accept peer_notify_reqid @{
			message("prefriend_message: notify_accept %s\n",
					peerNotifyReqid() );
			type = NotifyAccept;
		} |
		registered peer_notify_reqid friend_claim_sig_key
		@{
			message("prefriend_message: registered %s\n",
					peerNotifyReqid() );
			type = Registered;
		};

}%%

%% write data;

Parser::Control PrefriendParser::data( const char *data, int dlen )
{
	type = Unknown;
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * User-User messages
 */

#define MP_BROADCAST_KEY                      1
#define MP_ENCRYPT_REMOTE_BROADCAST_AUTHOR    2
#define MP_ENCRYPT_REMOTE_BROADCAST_SUBJECT   3
#define MP_REPUB_REMOTE_BROADCAST_PUBLISHER   4
#define MP_REPUB_REMOTE_BROADCAST_AUTHOR      5
#define MP_REPUB_REMOTE_BROADCAST_SUBJECT     6
#define MP_RETURN_REMOTE_BROADCAST_AUTHOR     7
#define MP_RETURN_REMOTE_BROADCAST_SUBJECT    8
#define MP_BROADCAST_SUCCESS_AUTHOR           9
#define MP_BROADCAST_SUCCESS_SUBJECT          10
#define MP_USER_MESSAGE                       11

Allocated consBroadcastKey( const String &distName, long long generation, const String &bkKeys )
{
	long length = 1 + 
			stringLength( distName ) +
			sixtyFourBitLength() + 
			binLength( bkKeys );
	
	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_BROADCAST_KEY );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, bkKeys );

	return packet.relinquish();
}

Allocated consEncryptRemoteBroadcastAuthor( 	
		const String &authorReturnReqid, const String &floginToken, const String &distName, 
		long long generation, const String &recipients, const String &plainMsg )
{
	long length = 1 + 
			stringLength( authorReturnReqid ) +
			stringLength( floginToken ) +
			stringLength( distName ) +
			sixtyFourBitLength() +
			binLength( recipients ) +
			binLength( plainMsg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_ENCRYPT_REMOTE_BROADCAST_AUTHOR );
	dest = writeString( dest, authorReturnReqid );
	dest = writeString( dest, floginToken );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, recipients );
	dest = writeBin( dest, plainMsg );

	return packet.relinquish();
}

Allocated consEncryptRemoteBroadcastSubject(
		const String &reqid, const String &authorHash, const String &distName, 
		long long generation, const String &recipients, const String &plainMsg )
{
	long length = 1 + 
			stringLength( reqid ) +
			stringLength( authorHash ) +
			stringLength( distName ) +
			sixtyFourBitLength() +
			binLength( recipients ) + 
			binLength( plainMsg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_ENCRYPT_REMOTE_BROADCAST_SUBJECT );
	dest = writeString( dest, reqid );
	dest = writeString( dest, authorHash );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, recipients );
	dest = writeBin( dest, plainMsg );

	return packet.relinquish();
}

Allocated consRepubRemoteBroadcastPublisher(
		const String &messageId, const String &distName,
		long long generation, const String &recipients )
{
	long length = 1 + 
			stringLength( messageId ) +
			stringLength( distName ) +
			sixtyFourBitLength() +
			binLength( recipients );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_REPUB_REMOTE_BROADCAST_PUBLISHER );
	dest = writeString( dest, messageId );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, recipients );

	return packet.relinquish();
}

Allocated consRepubRemoteBroadcastAuthor(
		const String &publisher, const String &messageId,
		const String &distName, long long generation,
		const String &recipients )
{
	long length = 1 + 
			stringLength( publisher ) +
			stringLength( messageId ) +
			stringLength( distName ) +
			sixtyFourBitLength() +
			binLength( recipients );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_REPUB_REMOTE_BROADCAST_AUTHOR );
	dest = writeString( dest, publisher );
	dest = writeString( dest, messageId );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, recipients );

	return packet.relinquish();
}

Allocated consRepubRemoteBroadcastSubject(
		const String &publisher, const String &messageId,
		const String &distName, long long generation, 
		const String &recipients )
{
	long length = 1 + 
			stringLength( publisher ) +
			stringLength( messageId ) +
			stringLength( distName ) +
			sixtyFourBitLength() +
			binLength( recipients );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_REPUB_REMOTE_BROADCAST_SUBJECT );
	dest = writeString( dest, publisher );
	dest = writeString( dest, messageId );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, recipients );

	return packet.relinquish();
}

Allocated consReturnRemoteBroadcastAuthor(
		const String &reqid, const String &encPacket )
{
	long length = 1 + 
			stringLength( reqid ) +
			binLength( encPacket );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_RETURN_REMOTE_BROADCAST_AUTHOR );
	dest = writeString( dest, reqid );
	dest = writeBin( dest, encPacket );

	return packet.relinquish();
}

Allocated consReturnRemoteBroadcastSubject(
		const String &returnReqid, const String &encPacket )
{
	long length = 1 + 
			stringLength( returnReqid ) +
			binLength( encPacket );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_RETURN_REMOTE_BROADCAST_SUBJECT );
	dest = writeString( dest, returnReqid );
	dest = writeBin( dest, encPacket );

	return packet.relinquish();
}

Allocated consBroadcastSuccessAuthor( const String &messageId )
{
	long length = 1 + 
			stringLength( messageId );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_BROADCAST_SUCCESS_AUTHOR );
	dest = writeString( dest, messageId );

	return packet.relinquish();
}

Allocated consBroadcastSuccessSubject( const String &messageId )
{
	long length = 1 + 
			stringLength( messageId );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_BROADCAST_SUCCESS_SUBJECT );
	dest = writeString( dest, messageId );

	return packet.relinquish();
}

Allocated consUserMessage( const String &msg )
{
	long length = 1 + 
			binLength( msg );

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, MP_USER_MESSAGE );
	dest = writeBin( dest, msg );

	return packet.relinquish();
}

/*
 * message_parser
 */

%%{
	machine message_parser;

	include common "common.rl";

	broadcast_key = 1;
	encrypt_remote_broadcast_author = 2;
	encrypt_remote_broadcast_subject = 3;
	repub_remote_broadcast_publisher = 4;
	repub_remote_broadcast_author = 5;
	repub_remote_broadcast_subject = 6;
	return_remote_broadcast_author = 7;
	return_remote_broadcast_subject = 8;
	broadcast_success_author = 9;
	broadcast_success_subject = 10;
	user_message = 11;

	main := (
		broadcast_key dist_name0 generation64 body
			@{
				message( "message: broadcast_key %s %lld\n",
						distName(), generation );
				type = BroadcastKey;
			} |
		encrypt_remote_broadcast_author reqid0 token0 dist_name0 generation64 recipients body
			@{
				message( "message: encrypt_remote_broadcast_author %s %s %s %lld %ld\n", 
						reqid(), token(), distName(), generation, length );
				type = EncryptRemoteBroadcastAuthor;
			} |
		encrypt_remote_broadcast_subject reqid0 hash0 dist_name0 generation64 recipients body
			@{
				message( "message: encrypt_remote_broadcast_subject %s %s %s %lld %ld\n", 
						reqid(), hash(), distName(), generation, length );
				type = EncryptRemoteBroadcastSubject;
			} |
		repub_remote_broadcast_publisher message_id0 dist_name0 generation64 body
			@{
				message( "message: repub_remote_broadcast_publisher\n" );
				type = RepubRemoteBroadcastPublisher;
			} |
		repub_remote_broadcast_author iduri0 message_id0 dist_name0 generation64 body
			@{
				message( "message: repub_remote_broadcast_author\n" );
				type = RepubRemoteBroadcastAuthor;
			} |
		repub_remote_broadcast_subject iduri0 message_id0 dist_name0 generation64 body
			@{
				message( "message: repub_remote_broadcast_subject\n" );
				type = RepubRemoteBroadcastSubject;
			} |
		return_remote_broadcast_author reqid0 body
			@{
				message( "message: return_remote_broadcast_author %s %ld\n",
						reqid(), length );
				type = ReturnRemoteBroadcastAuthor;
			} |
		return_remote_broadcast_subject reqid0 body
			@{
				message( "message: return_remote_broadcast_subject %s %ld\n",
						reqid(), length );
				type = ReturnRemoteBroadcastSubject;
			} |
		broadcast_success_author message_id0
			@{
				message( "message: broadcast_success_author %s\n", messageId() );
				type = BroadcastSuccessAuthor;
			} |
		broadcast_success_subject message_id0
			@{
				message( "message: broadcast_success_subject %s\n", messageId() );
				type = BroadcastSuccessSubject;
			} |
		user_message body
			@{
				message( "message: user_message\n" );
				type = UserMessage;
			}
	)*;
}%%

%% write data;

Parser::Control MessageParser::data( const char *data, int dlen )
{
	%% write init;

	const unsigned char *p = (u_char*) data;
	const unsigned char *pe = (u_char*)data + dlen;
	type = Unknown;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

#define FOF_MP_FETCH_RB_BROADCAST_KEY 1

Allocated consFetchRbBroadcastKey( const String distName, long long generation, const String &memberProof )
{
	long length = 1 + 
		stringLength( distName ) +
		sixtyFourBitLength() +
		binLength( memberProof );
	
	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, FOF_MP_FETCH_RB_BROADCAST_KEY );
	dest = writeString( dest, distName );
	dest = write64Bit( dest, generation );
	dest = writeBin( dest, memberProof );

	return packet.relinquish();
}

/*
 * fof_message_parser
 */

%%{
	machine fof_message_parser;

	include common "common.rl";

	fetch_rb_broadcast_key = 1;

	member_proof =
		bin16 @{
			memberProof.set( buf );
		};

	main := (
		fetch_rb_broadcast_key dist_name0 generation64 member_proof
			@{
				message( "message: fetch_rb_broadcast_key %s %lld\n", distName(), generation );
				type = FetchRbBroadcastKey;
			}
	)*;
}%%

%% write data;

Parser::Control FofMessageParser::data( const char *data, int dlen )
{
	%% write init;

	const unsigned char *p = (u_char*) data;
	const unsigned char *pe = (u_char*)data + dlen;
	type = Unknown;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

Allocated Server::fetchPublicKeyNet( const String &host, const String &user )
{
	message( "fetching public key for %s from %s\n", user(), host() );
	TlsConnect tlsConnect( c, tlsContext );

	/* Connect and send the public key request. */
	tlsConnect.connect( host );
	String publicKey = consPublicKey( user );
	tlsConnect.write( publicKey );

	/* Parse the result. */
	ResponseParser parser;
	tlsConnect.readParse( parser );

	if ( parser.body.length == 0 )
		throw ParseError( __FILE__, __LINE__ );

	return parser.body.relinquish();
}

Allocated Server::fetchRequestedRelidNet( const String &host,
		const String &reqid )
{
	TlsConnect tlsConnect( c, tlsContext );

	tlsConnect.connect( host );

	/* Send the request. */
	String fetchRequestedRelid = consFetchRequestedRelid( reqid );
	tlsConnect.write( fetchRequestedRelid );

	/* Parse the result. */
	ResponseParser parser;
	tlsConnect.readParse( parser );

	if ( parser.body.length == 0 )
		throw ParseError( __FILE__, __LINE__ );

	/* Output. */
	return parser.body.relinquish();
}

Allocated Server::fetchResponseRelidNet( const String &host,
		const String &reqid )
{
	TlsConnect tlsConnect( c, tlsContext );

	tlsConnect.connect( host );

	/* Send the request. */
	String fetchResponseRelid = consFetchResponseRelid( reqid );
	tlsConnect.write( fetchResponseRelid );

	/* Parse the result. */
	ResponseParser parser;
	tlsConnect.readParse( parser );

	if ( parser.body.length == 0 )
		throw ParseError( __FILE__, __LINE__ );

	/* Output. */
	return parser.body.relinquish();
}

Allocated Server::fetchFtokenNet( const String &host,
		const String &reqid )
{
	TlsConnect tlsConnect( c, tlsContext );

	tlsConnect.connect( host );

	/* Send the request. */
	String fetchFtoken = consFetchFtoken( reqid );
	tlsConnect.write( fetchFtoken );

	/* Parse the result. */
	ResponseParser parser;
	tlsConnect.readParse( parser );

	if ( parser.body.length == 0 )
		throw ParseError( __FILE__, __LINE__ );

	/* Output. */
	return parser.body.relinquish();
}

Allocated Server::sendMessageNet( const String &host,
		const String &relid, const String &msg )
{
	TlsConnect tlsConnect( c, tlsContext );
	ResponseParser parser;

	tlsConnect.connect( host );

	/* Send the request. */
	String message = consMessage( relid, msg );
	tlsConnect.write( message );

	tlsConnect.readParse( parser );

	return parser.body.length > 0 ?
			parser.body.relinquish() : Allocated();
}

Allocated Server::sendFofMessageNet( const String &host,
		const String &relid, const String &msg )
{
	message( "sending FOF message NET\n" );

	TlsConnect tlsConnect( c, tlsContext );
	ResponseParser parser;

	tlsConnect.connect( host );

	/* Send the request. */
	String fofMessage = consFofMessage( relid, msg );
	tlsConnect.write( fofMessage );

	tlsConnect.readParse( parser );

	return parser.body.length > 0 ?
			parser.body.relinquish() : Allocated();
}

void Server::sendBroadcastNet( const String &host,
		RecipientList &recipientList, const String &network,
		long long keyGen, const String &msg )
{
	TlsConnect tlsConnect( c, tlsContext );
	tlsConnect.connect( host );
	
	for ( RecipientList::iterator r = recipientList.begin(); r != recipientList.end(); r++ ) {
		/* FIXME: catch errors here. */
		String relid = Pointer( r->c_str() );
		String broadcastReceipient = consBroadcastRecipient( relid );
		tlsConnect.write( broadcastReceipient );

		ResponseParser parser;
		tlsConnect.readParse( parser );
		if ( parser.body.length > 0 )
			throw ParseError( __FILE__, __LINE__ );
	}

	/* Send the request. */
	String broadcast = consBroadcast( network, keyGen, msg );
	tlsConnect.write( broadcast );

	ResponseParser parser;
	tlsConnect.readParse( parser );

	if ( parser.body.length > 0 )
		throw ParseError( __FILE__, __LINE__ );
}

