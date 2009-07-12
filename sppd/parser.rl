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
	type = [a-zA-Z]+          >{mark=p;} %{type.set(mark, p);};

	date = ( 
		digit{4} '-' digit{2} '-' digit{2} ' ' 
		digit{2} ':' digit{2} ':' digit{2} 
	)
	>{mark=p;} %{date.set(mark, p);};

	path_part = (graph-'/')+;

	identity = 
		( 'https://' path_part '/' ( path_part '/' )* )
		>{mark=p;} %{identity.set(mark, p);};

	generation = [0-9]+       >{mark=p;} %{gen_str.set(mark, p);};
	number = [0-9]+           >{mark=p;} %{number.set(mark, p);};
	seq_num = [0-9]+          >{mark=p;} %{seq_str.set(mark, p);};
	resource_id = [0-9]+      >{mark=p;} %{resource_id_str.set(mark, p);};

	EOL = '\r'? '\n';
}%%

%%{
	machine parser;

	include common;

	action new_user { new_user( mysql, user, pass, email ); }
	action public_key { public_key( mysql, user ); }

	action relid_request {
		relid_request( mysql, user, identity );
	}

	action fetch_requested_relid {
		fetch_requested_relid( mysql, reqid );
	}

	action relid_response {
		relid_response( mysql, user, reqid, identity );
	}

	action fetch_response_relid {
		fetch_response_relid( mysql, reqid );
	}

	action friend_final {
		friend_final( mysql, user, reqid, identity );
	}

	action accept_friend {
		accept_friend( mysql, user, reqid );
	}

	action ftoken_request {
		ftoken_request( mysql, user, hash );
	}

	action ftoken_response {
		message("calling ftoken_response\n");
		ftoken_response( mysql, user, hash, reqid );
	}

	action fetch_ftoken {
		fetch_ftoken( mysql, reqid );
	}

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

	action receive_message {
		long length = atoi( number );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		receive_message( mysql, relid, user_message );
	}

	action notify_accept {
		long length = atoi( number );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		notify_accept( mysql, relid, user_message );
	}

	action broadcast {
		long long generation = strtoll( gen_str, 0, 10 );
		long length = atoi( number );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		broadcast( mysql, relid, generation, user_message );
	}

	action submit_broadcast {
		long long resource_id = strtoll( resource_id_str, 0, 10 );
		int length = atoi( number );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		submit_broadcast( mysql, user, type, resource_id, user_message, length );
		free( user_message );
	}

	action submit_remote_broadcast {
		int length = atoi( number );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		submit_remote_broadcast( mysql, user, identity, hash, token, type, user_message, length );
		free( user_message );
	}

	action login {

		login( mysql, user, pass );
	}

	action submit_ftoken {
		submit_ftoken( mysql, token );
	}

	action remote_publish {
		long long seq_num = strtoll( seq_str, 0, 10 );
		int length = atoi( number );
		if ( length > MAX_MSG_LEN )
			fgoto *parser_error;

		char *user_message = new char[length+1];
		BIO_read( bioIn, user_message, length );
		user_message[length] = 0;

		remote_publish( mysql, user, identity, token, seq_num, type, user_message );
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
		'notify_accept'i ' ' relid ' ' number EOL @check_ssl @notify_accept;

		# Friend login. 
		'ftoken_request'i ' ' user ' ' hash EOL @check_key @ftoken_request;
		'ftoken_response'i ' ' user ' ' hash ' ' reqid
				EOL @check_key @ftoken_response;
		'fetch_ftoken'i ' ' reqid EOL @check_ssl @fetch_ftoken;
		'submit_ftoken'i ' ' token EOL @check_key @submit_ftoken;

		'submit_broadcast'i ' ' user ' ' type ' ' resource_id ' ' number EOL @check_key @submit_broadcast;
		'submit_remote_broadcast'i ' ' user ' ' identity ' ' hash ' ' token ' '
				type ' ' number EOL @check_key @submit_remote_broadcast;

		'message'i ' ' relid ' ' number EOL @check_ssl @receive_message;
		'broadcast'i ' ' relid ' ' generation ' ' number EOL @check_ssl @broadcast;
		'remote_publish'i ' ' user ' ' identity ' ' token ' ' seq_num ' ' type ' ' number 
				EOL @check_ssl @remote_publish;
	*|;

	main := 'SPP/0.1'i ' ' identity %set_config EOL @{ fgoto commands; };
}%%

%% write data;

const long linelen = 4096;

int server_parse_loop()
{
	long cs, act;
	const char *mark;
	const char *ts, *te;
	String user, pass, email, identity, number, reqid, hash, key, relid, token, type;
	String gen_str, seq_str, resource_id_str;

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

		message("parse_loop: parsing a line: %s", buf );

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
 * notify_accept_parser
 */

%%{
	machine notify_accept_parser;

	include common;

	action accept {
		accept( mysql, user, friend_id, id_salt, requested_relid, returned_relid );
	}

	action registered {
		registered( mysql, user, friend_id, requested_relid, returned_relid );
	}

	main :=
		'accept'i ' ' id_salt ' ' requested_relid ' ' returned_relid EOL @accept |
		'registered'i ' ' requested_relid ' ' returned_relid EOL @registered;
}%%

%% write data;

int notify_accept_parser( MYSQL *mysql, const char *relid,
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

	action broadcast_key {
		broadcast_key( mysql, to_relid, user, friend_id, gen_str, key );
	}

	action forward_to {
		forward_to( mysql, user, friend_id, number, identity, relid );
	}

	main :=
		'broadcast_key'i ' ' generation ' ' key EOL @broadcast_key |
		'forward_to'i ' ' number ' ' identity ' ' relid EOL @forward_to;
}%%

%% write data;

int message_parser( MYSQL *mysql, const char *to_relid,
		const char *user, const char *friend_id, const char *message )
{
	long cs;
	const char *mark;
	String identity, number, key, relid, gen_str;

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
 * broadcast_parser
 */

%%{
	machine broadcast_parser;

	include common;

	action direct_broadcast {
		long long seq_num = strtoll( seq_str, 0, 10 );
		long long resource_id = strtoll( resource_id_str, 0, 10 );

		long length = atoi( number );
		if ( length > MAX_MSG_LEN ) {
			message("message too large\n");
			fgoto *parser_error;
		}

		/* Rest of the input is the msssage. */
		const char *msg = p + 1;
		direct_broadcast( mysql, relid, user, friend_id, seq_num, date, type, resource_id, msg, length );
		fbreak;
	}

	action remote_broadcast {
		long long generation = strtoll( gen_str, 0, 10 );
		long length = atoi( number );
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
		'direct_broadcast'i ' ' seq_num ' ' date ' ' type ' ' resource_id ' ' number EOL @direct_broadcast |
		'remote_broadcast'i ' ' hash ' ' generation ' ' number EOL @remote_broadcast;
}%%

%% write data;

int broadcast_parser( MYSQL *mysql, const char *relid,
		const char *user, const char *friend_id, const char *msg, long mLen )
{
	long cs;
	const char *mark;
	String date, number, hash, type, seq_str, gen_str, resource_id_str;

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

	return 0;
}

/*
 * remote_broadcast_parser
 */

%%{
	machine remote_broadcast_parser;

	include common;

	action remote_inner {
		long long seq_num = strtoll( seq_str, 0, 10 );
		long length = atoi( number );
		if ( length > MAX_MSG_LEN ) {
			message("message too large\n");
			fgoto *parser_error;
		}

		/* Rest of the input is the msssage. */
		const char *msg = p + 1;
		remote_inner( mysql, user, friend_id, author_id, seq_num, date, type, msg, length );
		fbreak;
	}

	main :=
		'remote_inner'i ' ' seq_num ' ' date ' ' type ' ' number EOL @remote_inner;

}%%

%% write data;

int remote_broadcast_parser( MYSQL *mysql, const char *user,
		const char *friend_id, const char *author_id, const char *msg, long mLen )
{
	long cs;
	const char *mark;
	String date, number, type, seq_str;

	message("parsing remote_broadcast string: %s\n", msg );

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
	message("encrypted return to fetch_public_key_net is %s", buf );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		include common;

		n = base64   >{n1 = p;} %{n2 = p;};
		e = base64   >{e1 = p;} %{e2 = p;};

		main := 
			'OK ' n ' ' e EOL @{ OK = true; } |
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

	message("fetch_public_key_net returning %s %s\n", pub.n, pub.e );

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
	bool OK = false;
	const char *mark;
	String sym;

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
	message("encrypted return to fetch_requested_relid is %s", buf );

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
	
	encsig.sym = sym.relinquish();

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
	bool OK = false;
	const char *p, *pe;
	const char *mark;
	String sym;

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
	
	encsig.sym = sym.relinquish();

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
	bool OK = false;
	const char *p, *pe;
	const char *mark;
	String sym;

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
	if ( cs < %%{ write first_final; }%%  ) {
		result = ERR_PARSE_ERROR;
		goto fail;
	}
	
	if ( !OK ) {
		result = ERR_SERVER_ERROR;
		goto fail;
	}
	
	encsig.sym = sym.relinquish();

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
 * send_notify_accept_net
 */

%%{
	machine send_notify_accept_net;
	write data;
}%%

long send_notify_accept_net( MYSQL *mysql, const char *from_user, const char *to_identity, const char *relid,
		const char *message, long mLen, char **result_message )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	bool OK = false;
	long pres;
	const char *mark;
	String number;

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
	BIO_printf( sbio, "notify_accept %s %ld\r\n", relid, mLen );
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
		include common;

		action result {
			long length = strtoll( number, 0, 10 );
			if ( length > MAX_MSG_LEN )
				fgoto *parser_error;

			char *user_message = new char[length+1];
			BIO_read( sbio, user_message, length );
			user_message[length] = 0;

			::message( "about to decrypt RESULT\n" );

			if ( result_message != 0 ) 
				*result_message = decrypt_result( mysql, from_user, to_identity, user_message );
			::message( "finished with decrypt RESULT\n" );
		}

		main := 
			'OK' EOL @{ OK = true; } |
			'RESULT' ' ' number EOL @result |
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

long send_message_net( MYSQL *mysql, const char *from_user, const char *to_identity, const char *relid,
		const char *message, long mLen, char **result_message )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	bool OK = false;
	long pres;
	const char *mark;
	String number;

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
	BIO_printf( sbio, "message %s %ld\r\n", relid, mLen );
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
		include common;

		action result {
			long length = strtoll( number, 0, 10 );
			if ( length > MAX_MSG_LEN )
				fgoto *parser_error;

			char *user_message = new char[length+1];
			BIO_read( sbio, user_message, length );
			user_message[length] = 0;

			::message( "about to decrypt RESULT\n" );

			if ( result_message != 0 ) 
				*result_message = decrypt_result( mysql, from_user, to_identity, user_message );
			::message( "finished with decrypt RESULT\n" );
		}

		main := 
			'OK' EOL @{ OK = true; } |
			'RESULT' ' ' number EOL @result |
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
		const char *token, long long seq_num,
		const char *type, const char *msg, long mLen )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	bool OK = false;
	long pres;
	const char *mark;
	String number, sym;

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
		"remote_publish %s %s%s/ %s %lld %s %ld\r\n", 
		toIdent.user, c->CFG_URI, from_user, token, seq_num, type, mLen );
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
		include common;

		main := 
			'OK' ' ' number ' ' sym EOL @{ OK = true; } |
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

	resultGen = strtoll( number, 0, 10 );
	resultEnc = sym.relinquish();

	::message( "resultGen: %lld\n", resultGen );
	
fail:
	::close( socketFd );
	return result;
}

%%{
	machine base64;
	write data;
}%%

char *bin_to_base64( const u_char *data, long len )
{
	const char *index = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	long group;
	long lenRem = len % 3;
	long lenEven = len - lenRem;

	long outLen = ( lenEven / 3 ) * 4 + ( lenRem > 0 ? 4 : 0 ) + 1;
	char *output = new char[outLen];
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

	*dest = 0;

	return output;

}

long base64_to_bin( unsigned char *out, long len, const char *src )
{
	long sixBits;
	long group;
	unsigned char *dest = out;

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
		main := group* short? 0;
			
	}%%

	/* Note: including the null. */
	const char *p = src;
	const char *pe = src + strlen(src) + 1;
	int cs;

	%% write init;
	%% write exec;

	/* Did parsing succeed? */
	if ( cs < %%{ write first_final; }%% )
		return 0;

	return dest - out;
}

