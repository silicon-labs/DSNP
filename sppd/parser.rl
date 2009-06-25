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
#include "sppd.h"

#define MAX_MSG_LEN 16384

bool gblKeySubmitted = false;

/* FIXME: check all scanned lengths for overflow. */

char *alloc_string( const char *s, const char *e )
{
	long length = e-s;
	char *result = (char*)malloc( length+1 );
	memcpy( result, s, length );
	result[length] = 0;
	return result;
}

%%{
	machine common;

	user = [a-zA-Z0-9_.]+     >{u1=p;} %{u2=p;};
	pass = graph+             >{p1=p;} %{p2=p;};
	email = graph+            >{e1=p;} %{e2=p;};
	path_part = (graph-'/')+  >{pp1=p;} %{pp2=p;};
	reqid = [0-9a-f]+         >{r1=p;} %{r2=p;};
	hash = [0-9a-f]+          >{a1=p;} %{a2=p;};
	key = [a-f0-9]+           >{k1=p;} %{k2=p;};
	enc = [0-9a-f]+           >{e1=p;} %{e2=p;};
	sig = [0-9a-f]+           >{s1=p;} %{s2=p;};
	sig1 = [0-9a-f]+          >{s1=p;} %{s2=p;};
	sig2 = [0-9a-f]+          >{t1=p;} %{t2=p;};
	sym = [0-9a-f]+           >{y1=p;} %{y2=p;};
	generation = [0-9]+       >{g1=p;} %{g2=p;};
	relid = [0-9a-f]+         >{r1=p;} %{r2=p;};
	token = [0-9a-f]+         >{t1=p;} %{t2=p;};

	date = ( digit{4} '-' digit{2} '-' digit{2} ' '
			digit{2} ':' digit{2} ':' digit{2} ) >{d1 = p;} %{d2 = p;};

	identity = 
		( 'https://' path_part >{h1=p;} %{h2=p;} '/' ( path_part '/' )* )
		>{i1=p;} %{i2=p;};

	identity2 = 
		( 'https://' path_part '/' ( path_part '/' )* )
		>{j1=p;} %{j2=p;};

	number = [0-9]+           >{n1=p;} %{n2=p;};
	seq_num = [0-9]+          >{q1=p;} %{q2=p;};

	EOL = '\r'? '\n';
}%%

%%{
	machine parser;

	include common;

	action new_user {
		char *user = alloc_string( u1, u2 );
		char *pass = alloc_string( p1, p2 );
		char *email = alloc_string( e1, e2 );

		new_user( mysql, user, pass, email );
	}

	action public_key {
		char *user = alloc_string( u1, u2 );

		public_key( mysql, user );
	}

	action relid_request {
		char *user = alloc_string( u1, u2 );
		char *identity = alloc_string( i1, i2 );

		relid_request( mysql, user, identity );
	}

	action fetch_requested_relid {
		char *reqid = alloc_string( r1, r2 );

		fetch_requested_relid( mysql, reqid );
	}

	action relid_response {
		char *user = alloc_string( u1, u2 );
		char *reqid = alloc_string( r1, r2 );
		char *identity = alloc_string( i1, i2 );
		char *id_host = alloc_string( h1, h2 );
		char *id_user = alloc_string( pp1, pp2 );

		relid_response( mysql, user, reqid, identity, id_host, id_user );
	}

	action fetch_response_relid {
		char *reqid = alloc_string( r1, r2 );

		fetch_response_relid( mysql, reqid );
	}

	action friend_final {
		char *user = alloc_string( u1, u2 );
		char *reqid = alloc_string( r1, r2 );
		char *identity = alloc_string( i1, i2 );
		char *id_host = alloc_string( h1, h2 );
		char *id_user = alloc_string( pp1, pp2 );

		friend_final( mysql, user, reqid, identity, id_host, id_user );
	}

	action accept_friend {
		char *user = alloc_string( u1, u2 );
		char *reqid = alloc_string( r1, r2 );

		accept_friend( mysql, user, reqid );
	}

	action ftoken_request {
		char *user = alloc_string( u1, u2 );
		char *hash = alloc_string( a1, a2 );

		ftoken_request( mysql, user, hash );
	}

	action ftoken_response {
		char *user = alloc_string( u1, u2 );
		char *hash = alloc_string( a1, a2 );
		char *reqid = alloc_string( r1, r2 );

		ftoken_response( mysql, user, hash, reqid );
	}

	action fetch_ftoken {
		char *reqid = alloc_string( r1, r2 );
		fetch_ftoken( mysql, reqid );
	}

	action set_config {
		char *identity = alloc_string( i1, i2 );
		set_config_by_uri( identity );

		/* Now that we have a config connect to the database. */
		mysql = db_connect();
		if ( mysql == 0 )
			fgoto *parser_error;
	}

	action comm_key {
		char *key = alloc_string( k1, k2 );
		
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

	action receive_message {
		char *relid = alloc_string( r1, r2 );
		char *lengthStr = alloc_string( n1, n2 );

		long length = atoi( lengthStr );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		receive_message( mysql, relid, user_message );
	}

	action broadcast {
		char *relid = alloc_string( r1, r2 );
		char *generation_str = alloc_string( g1, g2 );
		long long generation = strtoll( generation_str, 0, 10 );
		char *length_str = alloc_string( n1, n2 );

		long length = atoi( length_str );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		broadcast( mysql, relid, generation, user_message );
	}

	action submit_broadcast {
		char *user = alloc_string( u1, u2 );
		char *number = alloc_string( n1, n2 );

		int length = atoi( number );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		submit_broadcast( mysql, user, user_message, length );
		free( user_message );
	}

	action submit_remote_broadcast {
		char *user = alloc_string( u1, u2 );
		char *identity = alloc_string( i1, i2 );
		char *token = alloc_string( t1, t2 );
		char *number = alloc_string( n1, n2 );

		int length = atoi( number );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		submit_remote_broadcast( mysql, user, identity, token, user_message, length );
		free( user_message );
	}

	action login {
		char *user = alloc_string( u1, u2 );
		char *pass = alloc_string( p1, p2 );

		login( mysql, user, pass );
	}

	action submit_ftoken {
		char *token = alloc_string( t1, t2 );
		submit_ftoken( mysql, token );
	}

	action remote_publish {
		char *user = alloc_string( u1, u2 );
		char *identity = alloc_string( i1, i2 );
		char *token = alloc_string( t1, t2 );
		char *number = alloc_string( n1, n2 );

		int length = atoi( number );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		remote_publish( mysql, user, identity, token, user_message );
		free( user_message );
	}

	action start_tls {
		start_tls();
		ssl = true;
	}

	commands := |* 
		'comm_key'i ' ' key EOL @comm_key;
		'start_tls'i EOL @start_tls;
		'login'i ' ' user ' ' pass EOL @check_key @login;

		# Admin commands.
		'new_user'i ' ' user ' ' pass ' ' email EOL @check_key @new_user;

		# Public key sharing.
		'public_key'i ' ' user EOL @check_ssl @public_key;

		# Friend Request.
		'relid_request'i ' ' user ' ' identity EOL @check_key @relid_request;
		'relid_response'i ' ' user ' ' reqid ' ' identity
				EOL @check_key @relid_response;
		'friend_final'i ' ' user ' ' reqid ' ' identity
				EOL @check_key @friend_final;
		'fetch_requested_relid'i ' ' reqid EOL @check_ssl @fetch_requested_relid;
		'fetch_response_relid'i ' ' reqid EOL @check_ssl @fetch_response_relid;

		# Friend Request Accept
		'accept_friend'i ' ' user ' ' reqid EOL @check_key @accept_friend;

		# Friend login. 
		'ftoken_request'i ' ' user ' ' hash EOL @check_key @ftoken_request;
		'ftoken_response'i ' ' user ' ' hash ' ' reqid
				EOL @check_key @ftoken_response;
		'fetch_ftoken'i ' ' reqid EOL @check_ssl @fetch_ftoken;
		'submit_ftoken'i ' ' token EOL @check_key @submit_ftoken;

		'submit_broadcast'i ' ' user ' ' number EOL @check_key @submit_broadcast;
		'submit_remote_broadcast'i ' ' user ' ' identity ' ' token ' '
				number EOL @check_key @submit_remote_broadcast;

		'message'i ' ' relid ' ' number EOL @check_ssl @receive_message;
		'broadcast'i ' ' relid ' ' generation ' ' number EOL @check_ssl @broadcast;
		'remote_publish'i ' ' user ' ' identity ' ' token ' ' number 
				EOL @check_ssl @remote_publish;
	*|;

	main := 'SPP/0.1'i ' ' identity %set_config EOL @{ fgoto commands; };
}%%

%% write data;

const long linelen = 4096;

int server_parse_loop()
{
	long cs, act;
	const char *k1, *k2;
	const char *ts, *te;
	const char *u1, *u2;
	const char *p1, *p2;
	const char *e1, *e2;
	const char *i1, *i2;
	const char *h1, *h2;
	const char *pp1, *pp2;
	const char *r1, *r2;
	const char *a1, *a2;
	const char *n1, *n2;
	const char *t1, *t2;
	const char *g1, *g2;

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
		long length = strlen( buf );
		if ( buf[length-1] != '\n' ) {
			error( "line too long\n" );
			return ERR_LINE_TOO_LONG;
		}

		message("parse_loop: parsing a line: %s\n", buf );

		const char *p = buf, *pe = buf + length;

		%% write exec;

		if ( cs == parser_error ) {
			error( "parse error: %s", buf );
			return ERR_PARSE_ERROR;
		}
		else if ( cs < %%{ write first_final; }%% )
			return ERR_UNEXPECTED_END;
	}

	if ( mysql != 0 ) {
		run_broadcast_queue_db( mysql );
		run_message_queue_db( mysql );
	}

	return 0;
}

/*
 * message_parser
 */

%%{
	machine message_parser;

	include common;

	action session_key {
		char *generation = alloc_string( g1, g2 );
		char *sk = alloc_string( k1, k2 );

		session_key( mysql, relid, user, friend_id, generation, sk );
	}

	action forward_to {
		char *number = alloc_string( n1, n2 );
		char *to_identity = alloc_string( i1, i2 );
		char *relid = alloc_string( r1, r2 );

		forward_to( mysql, user, friend_id, number, to_identity, relid );
	}

	main :=
		'session_key'i ' ' generation ' ' key EOL @session_key |
		'forward_to'i ' ' number ' ' identity ' ' relid EOL @forward_to;
}%%

%% write data;

int message_parser( MYSQL *mysql, const char *relid,
		const char *user, const char *friend_id, const char *message )
{
	long cs;
	const char *k1, *k2;
	const char *i1, *i2;
	const char *h1, *h2;
	const char *pp1, *pp2;
	const char *g1, *g2;
	const char *n1, *n2;
	const char *r1, *r2;

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
	machine broadcast_parser;

	include common;

	action direct_broadcast {
		char *seqStr = alloc_string( q1, q2 );
		char *date = alloc_string( d1, d2 );
		char *lengthStr = alloc_string( n1, n2 );

		long long seqNum = strtoll( seqStr, 0, 10 );

		long length = atoi( lengthStr );
		if ( length > MAX_MSG_LEN ) {
			message("message too large\n");
			fgoto *parser_error;
		}

		/* Rest of the input is the msssage. */
		const char *msg = p + 1;
		direct_broadcast( mysql, relid, user, friend_id, seqNum, date, msg, length );
		fbreak;
	}

	action remote_broadcast {
		char *seqStr = alloc_string( q1, q2 );
		char *date = alloc_string( d1, d2 );
		char *hash = alloc_string( a1, a2 );
		char *genStr = alloc_string( g1, g2 );
		char *lengthStr = alloc_string( n1, n2 );

		long long seqNum = strtoll( seqStr, 0, 10 );
		long long generation = strtoll( genStr, 0, 10 );
		long length = atoi( lengthStr );
		if ( length > MAX_MSG_LEN ) {
			message("message too large\n");
			fgoto *parser_error;
		}

		/* Rest of the input is the msssage. */
		const char *msg = p + 1;
		remote_broadcast( mysql, relid, user, friend_id, seqNum, date,
			hash, generation, msg, length );
		fbreak;
	}

	main :=
		'direct_broadcast'i ' ' seq_num ' ' date ' ' number EOL @direct_broadcast |

		'remote_broadcast'i ' ' seq_num ' ' date ' ' hash ' ' generation ' ' number
			EOL @remote_broadcast;

}%%

%% write data;

int broadcast_parser( MYSQL *mysql, const char *relid,
		const char *user, const char *friend_id, const char *msg, long mLen )
{
	long cs;
	const char *d1, *d2;
	const char *n1, *n2;
	const char *a1, *a2;
	const char *g1, *g2;
	const char *q1, *q2;

	message("parsing broadcast string: %s\n", msg );

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
	long result = 0, cs;
	const char *p, *pe;
	const char *n1, *n2, *e1, *e2;
	bool OK = false;

	long socketFd = open_inet_connection( host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *buffer = BIO_new( BIO_f_buffer() );
	BIO_push( buffer, socketBio );

	/* Send the request. */
	BIO_printf( buffer,
		"SPP/0.1 %s\r\n"
		"start_tls\r\n",
		site );
	BIO_flush( buffer );

	/* Read the result. */
	int readRes = BIO_gets( buffer, buf, 8192 );
	message("return is %s", buf );

	sslInitClient();
	BIO *sbio = sslStartClient( socketBio, socketBio, host );

	BIO_printf( sbio, "public_key %s\r\n", user );
	BIO_flush( sbio );

	/* Read the result. */
	readRes = BIO_gets( sbio, buf, 8192 );
	message("encrypted return is %s", buf );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		EOL = '\r'? '\n';

		n = [0-9A-F]+  >{n1 = p;} %{n2 = p;};
		e = [01]+      >{e1 = p;} %{e2 = p;};

		main := 
			'OK ' n '/' e EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% ) {
		result = ERR_PARSE_ERROR;
		goto fail;
	}
	
	if ( !OK ) {
		result = ERR_SERVER_ERROR;
		goto fail;
	}
	
	pub.n = (char*)malloc( n2-n1+1 );
	pub.e = (char*)malloc( e2-e1+1 );
	memcpy( pub.n, n1, n2-n1 );
	memcpy( pub.e, e1, e2-e1 );
	pub.n[n2-n1] = 0;
	pub.e[e2-e1] = 0;

fail:
	::close( socketFd );
	return result;
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
	long result = 0, cs;
	const char *p, *pe;
	const char *y1, *y2;
	bool OK = false;

	long socketFd = open_inet_connection( host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *buffer = BIO_new( BIO_f_buffer() );
	BIO_push( buffer, socketBio );

	/* Send the request. */
	BIO_printf( buffer,
		"SPP/0.1 %s\r\n"
		"start_tls\r\n",
		site );
	BIO_flush( buffer );

	/* Read the result. */
	int readRes = BIO_gets( buffer, buf, 8192 );
	message("return is %s", buf );

	sslInitClient();
	BIO *sbio = sslStartClient( socketBio, socketBio, host );

	/* Send the request. */
	BIO_printf( sbio, "fetch_requested_relid %s\r\n", fr_reqid );
	BIO_flush( sbio );

	/* Read the result. */
	readRes = BIO_gets( sbio, buf, 8192 );
	message("encrypted return is %s", buf );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

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
	if ( cs < %%{ write first_final; }%% ) {
		result = ERR_PARSE_ERROR;
		goto fail;
	}
	
	if ( !OK ) {
		result = ERR_SERVER_ERROR;
		goto fail;
	}
	
	encsig.sym = (char*)malloc( y2-y1+1 );
	memcpy( encsig.sym, y1, y2-y1 );
	encsig.sym[y2-y1] = 0;

fail:
	::close( socketFd );
	return result;
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
	long result = 0, cs;
	const char *p, *pe;
	const char *y1, *y2;
	bool OK = false;

	long socketFd = open_inet_connection( host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *buffer = BIO_new( BIO_f_buffer() );
	BIO_push( buffer, socketBio );

	/* Send the request. */
	BIO_printf( buffer,
		"SPP/0.1 %s\r\n"
		"start_tls\r\n",
		site );
	BIO_flush( buffer );

	/* Read the result. */
	int readRes = BIO_gets( buffer, buf, 8192 );
	message("return is %s", buf );

	sslInitClient();
	BIO *sbio = sslStartClient( socketBio, socketBio, host );

	/* Send the request. */
	BIO_printf( sbio, "fetch_response_relid %s\r\n", reqid );
	BIO_flush( sbio );

	/* Read the result. */
	readRes = BIO_gets( sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		EOL = '\r'? '\n';

		enc = [0-9a-f]+      >{e1 = p;} %{e2 = p;};
		sig = [0-9a-f]+      >{s1 = p;} %{s2 = p;};
		sym = [0-9a-f]+      >{y1 = p;} %{y2 = p;};

		main := 
			'OK ' sym EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% ) {
		result = ERR_PARSE_ERROR;
		goto fail;
	}
	
	if ( !OK ) {
		result = ERR_SERVER_ERROR;
		goto fail;
	}
	
	encsig.sym = (char*)malloc( y2-y1+1 );
	memcpy( encsig.sym, y1, y2-y1 );
	encsig.sym[y2-y1] = 0;

fail:
	::close( socketFd );
	return result;
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
	long result = 0, cs;
	const char *p, *pe;
	const char *y1, *y2;
	bool OK = false;

	long socketFd = open_inet_connection( host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *buffer = BIO_new( BIO_f_buffer() );
	BIO_push( buffer, socketBio );

	/* Send the request. */
	BIO_printf( buffer,
		"SPP/0.1 %s\r\n"
		"start_tls\r\n",
		site );
	BIO_flush( buffer );

	/* Read the result. */
	int readRes = BIO_gets( buffer, buf, 8192 );
	message("return is %s", buf );

	sslInitClient();
	BIO *sbio = sslStartClient( socketBio, socketBio, host );

	/* Send the request. */
	BIO_printf( sbio, "fetch_ftoken %s\r\n", flogin_reqid );
	BIO_flush( sbio );

	/* Read the result. */
	readRes = BIO_gets( sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		EOL = '\r'? '\n';

		sym = [0-9a-f]+      >{y1 = p;} %{y2 = p;};

		main := 
			'OK ' sym EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%%  ) {
		result = ERR_PARSE_ERROR;
		goto fail;
	}
	
	if ( !OK ) {
		result = ERR_SERVER_ERROR;
		goto fail;
	}
	
	encsig.sym = (char*)malloc( y2-y1+1 );
	memcpy( encsig.sym, y1, y2-y1 );
	encsig.sym[y2-y1] = 0;

fail:
	::close( socketFd );
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
	long result = 0, cs;
	const char *p, *pe, *eof;

	const char *i1, *i2;
	const char *h1, *h2;
	const char *pp1, *pp2;

	/* Parser for response. */
	%%{
		include common;
		main := identity;
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

long send_broadcast_net( const char *toSite, const char *relid,
		long long generation, const char *msg, long mLen )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	bool OK = false;
	long pres;

	/* Need to parse the identity. */
	Identity site( toSite );
	pres = site.parse();

	if ( pres < 0 )
		return pres;

	long socketFd = open_inet_connection( site.host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *buffer = BIO_new( BIO_f_buffer() );
	BIO_push( buffer, socketBio );

	/* Send the request. */
	BIO_printf( buffer,
		"SPP/0.1 %s\r\n"
		"start_tls\r\n",
		toSite );
	BIO_flush( buffer );

	/* Read the result. */
	int readRes = BIO_gets( buffer, buf, 8192 );
	::message("return is %s", buf );

	sslInitClient();
	BIO *sbio = sslStartClient( socketBio, socketBio, site.host );

	/* Send the request. */
	BIO_printf( sbio, 
		"broadcast %s %lld %ld\r\n", 
		relid, generation, mLen );
	BIO_write( sbio, msg, mLen );
	BIO_flush( sbio );

	/* Read the result. */
	readRes = BIO_gets( sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		EOL = '\r'? '\n';

		main := 
			'OK' EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% ) {
		result = ERR_PARSE_ERROR;
		goto fail;
	}
	
	if ( !OK ) {
		result = ERR_SERVER_ERROR;
		goto fail;
	}
	
fail:
	::close( socketFd );
	return result;
}

/*
 * send_message_net
 */

%%{
	machine send_message_net;
	write data;
}%%

long send_message_net( const char *to_identity, const char *relid,
		const char *message, long mLen )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	bool OK = false;
	long pres;

	/* Need to parse the identity. */
	Identity toIdent( to_identity );
	pres = toIdent.parse();

	if ( pres < 0 )
		return pres;

	long socketFd = open_inet_connection( toIdent.host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *buffer = BIO_new( BIO_f_buffer() );
	BIO_push( buffer, socketBio );

	/* Send the request. */
	BIO_printf( buffer,
		"SPP/0.1 %s\r\n"
		"start_tls\r\n",
		toIdent.site );
	BIO_flush( buffer );

	/* Read the result. */
	int readRes = BIO_gets( buffer, buf, 8192 );
	::message("return is %s", buf );

	sslInitClient();
	BIO *sbio = sslStartClient( socketBio, socketBio, toIdent.host );

	/* Send the request. */
	BIO_printf( sbio, 
		"message %s %ld\r\n", 
		relid, mLen );
	BIO_write( sbio, message, mLen );
	BIO_flush( sbio );

	/* Read the result. */
	readRes = BIO_gets( sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		EOL = '\r'? '\n';

		main := 
			'OK' EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% ) {
		result = ERR_PARSE_ERROR;
		goto fail;
	}
	
	if ( !OK ) {
		result = ERR_SERVER_ERROR;
		goto fail;
	}
	
fail:
	::close( socketFd );
	return result;
}

	
/*
 * send_remote_publish_net
 */

%%{
	machine send_remote_publish_net;
	write data;
}%%

long send_remote_publish_net( char *&resultEnc, long long &resultGen,
		const char *to_identity, const char *from_user, 
		const char *token, const char *sym, long mLen )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	bool OK = false;
	long pres;
	char *number;

	/* Need to parse the identity. */
	Identity toIdent( to_identity );
	pres = toIdent.parse();

	if ( pres < 0 )
		return pres;

	long socketFd = open_inet_connection( toIdent.host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *buffer = BIO_new( BIO_f_buffer() );
	BIO_push( buffer, socketBio );

	/* Send the request. */
	BIO_printf( buffer,
		"SPP/0.1 %s\r\n"
		"start_tls\r\n",
		toIdent.site );
	BIO_flush( buffer );

	/* Read the result. */
	int readRes = BIO_gets( buffer, buf, 8192 );
	message("return is %s", buf );

	sslInitClient();
	BIO *sbio = sslStartClient( socketBio, socketBio, toIdent.host );

	/* Send the request. */
	BIO_printf( sbio, 
		"remote_publish %s %s%s/ %s %ld\r\n", 
		toIdent.user, c->CFG_URI, from_user, token, mLen );
	BIO_write( sbio, sym, mLen );
	BIO_flush( sbio );

	/* Read the result. */
	readRes = BIO_gets( sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		include common;

		main := 
			'OK' ' ' number ' ' sym EOL @{ OK = true; } |
			'ERROR' EOL;
	}%%

	p = buf;
	pe = buf + strlen(buf);
	const char *y1, *y2;
	const char *n1, *n2;

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% ) {
		result = ERR_PARSE_ERROR;
		goto fail;
	}
	
	if ( !OK ) {
		result = ERR_SERVER_ERROR;
		goto fail;
	}

	resultEnc = alloc_string( y1, y2 );
	number = alloc_string( n1, n2 );
	resultGen = strtoll( number, 0, 10 );

	::message( "resultGen: %lld\n", resultGen );
	
fail:
	::close( socketFd );
	return result;
}

%%{
	machine base64;
	write data;
}%%

char *binToBase64( const u_char *data, long len )
{
	const char *index = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	long twentyFourBits;
	long lenRem = len % 3;
	long lenEven = len - lenRem;

	long outLen = ( lenEven / 3 ) * 4 + ( lenRem > 0 ? 4 : 0 ) + 1;
	char *output = new char[outLen];
	char *dest = output;

	for ( int i = 0; i < lenEven; i += 3 ) {
		twentyFourBits = (long)data[i] << 16;
		twentyFourBits |= (long)data[i+1] << 8;
		twentyFourBits |= (long)data[i+2];

		*dest++ = index[( twentyFourBits >> 18 ) & 0x3f];
		*dest++ = index[( twentyFourBits >> 12 ) & 0x3f];
		*dest++ = index[( twentyFourBits >> 6 ) & 0x3f];
		*dest++ = index[twentyFourBits & 0x3f];
	}

	if ( lenRem > 0 ) {
		twentyFourBits = (long)data[lenEven] << 16;
		if ( lenRem > 1 )
			twentyFourBits |= (long)data[lenEven+1] << 8;

		/* Always need the first two six-bit groups.  */
		*dest++ = index[( twentyFourBits >> 18 ) & 0x3f];
		*dest++ = index[( twentyFourBits >> 12 ) & 0x3f];
		if ( lenRem > 1 )
			*dest++ = index[( twentyFourBits >> 6 ) & 0x3f];
		else
			*dest++ = '=';
		*dest++ = '=';
	}

	*dest = 0;

	return output;

}

long base64ToBin( unsigned char *out, long len, const char *src )
{
	long sixBits;
	long twentyFourBits;
	unsigned char *dest = out;

	/* Parser for response. */
	%%{
		sixBits = 
			[A-Z] @{ sixBits = *p - 'A'; } |
			[a-z] @{ sixBits = 26 + (*p - 'a'); } |
			[0-9] @{ sixBits = 52 + (*p - '0'); } |
			'+' @{ sixBits = 62; } |
			'/' @{ sixBits = 63; };

		action c1 {
			twentyFourBits = sixBits << 18;
		}
		action c2 {
			twentyFourBits |= sixBits << 12;
		}
		action c3 {
			twentyFourBits |= sixBits << 6;
		}
		action c4 {
			twentyFourBits |= sixBits;
		}

		action three {
			*dest++ = ( twentyFourBits >> 16 ) & 0xff;
			*dest++ = ( twentyFourBits >> 8 ) & 0xff;
			*dest++ = twentyFourBits & 0xff;
		}
		action two {
			*dest++ = ( twentyFourBits >> 16 ) & 0xff;
			*dest++ = ( twentyFourBits >> 8 ) & 0xff;
		}
		action one {
			*dest++ = ( twentyFourBits >> 16 ) & 0xff;
		}

		twentyFourBits =
			( sixBits @c1 sixBits @c2 sixBits @c3 sixBits @c4 ) @three |
			( sixBits @c1 sixBits @c2 sixBits '=') @two |
			( sixBits @c1 sixBits '=' '=' ) @one ;

		main := twentyFourBits*;
			
	}%%

	const char *p = src;
	const char *pe = src + strlen(src);
	int cs;

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return 0;

	return dest - out;
}

