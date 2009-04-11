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
#include "sppd.h"

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

	comm_key = [a-f0-9]+      >{k1=p;} %{k2=p;};
	user = [a-zA-Z0-9_.]+     >{u1=p;} %{u2=p;};
	pass = graph+             >{p1=p;} %{p2=p;};
	email = graph+            >{e1=p;} %{e2=p;};
	path_part = (graph-'/')+  >{pp1=p;} %{pp2=p;};
	reqid = [0-9a-f]+         >{r1=p;} %{r2=p;};
	hash = [0-9a-f]+          >{a1=p;} %{a2=p;};
	enc = [0-9a-f]+           >{e1=p;} %{e2= p;};
	sig = [0-9a-f]+           >{s1=p;} %{s2=p;};
	generation = [0-9]+       >{g1=p;} %{g2=p;};

	identity = 
		( 'http://' path_part >{h1=p;} %{h2=p;} '/' ( path_part '/' )* )
		>{i1=p;} %{i2=p;};

	identity2 = 
		( 'http://' path_part '/' ( path_part '/' )* )
		>{j1=p;} %{j2=p;};

	num = [a-f0-9]+      >{n1=p;} %{n2=p;};
}%%

%%{
	machine parser;

	include common;

	EOL = '\r'? '\n';

	action new_user {
		char *key = alloc_string( k1, k2 );
		char *user = alloc_string( u1, u2 );
		char *pass = alloc_string( p1, p2 );
		char *email = alloc_string( e1, e2 );
		new_user( key, user, pass, email );
		free( key );
		free( user );
		free( pass );
		free( email );
	}

	action public_key {
		char *user = alloc_string( u1, u2 );
		public_key( user );
		free( user );
	}

	action friend_req {
		char *user = alloc_string( u1, u2 );
		char *identity = alloc_string( i1, i2 );
		friend_req( user, identity );
		free( user );
		free( identity );
	}

	action fetch_fr_relid {
		char *reqid = alloc_string( r1, r2 );
		fetch_fr_relid( reqid );
		free( reqid );
	}

	action return_relid {
		char *user = alloc_string( u1, u2 );
		char *reqid = alloc_string( r1, r2 );
		char *identity = alloc_string( i1, i2 );
		char *id_host = alloc_string( h1, h2 );
		char *id_user = alloc_string( pp1, pp2 );
		return_relid( user, reqid, identity, id_host, id_user );
		free( user );
		free( reqid );
		free( identity );
		free( id_host );
		free( id_user );
	}

	action fetch_relid {
		char *reqid = alloc_string( r1, r2 );
		fetch_relid( reqid );
		free( reqid );
	}

	action friend_final {
		char *user = alloc_string( u1, u2 );
		char *reqid = alloc_string( r1, r2 );
		char *identity = alloc_string( i1, i2 );
		char *id_host = alloc_string( h1, h2 );
		char *id_user = alloc_string( pp1, pp2 );
		friend_final( user, reqid, identity, id_host, id_user );
		free( user );
		free( reqid );
		free( identity );
		free( id_host );
		free( id_user );
	}

	action accept_friend {
		char *key = alloc_string( k1, k2 );
		char *user = alloc_string( u1, u2 );
		char *reqid = alloc_string( r1, r2 );
		accept_friend( key, user, reqid );
		free( key );
		free( user );
		free( reqid );
	}

	action flogin {
		char *user = alloc_string( u1, u2 );
		char *hash = alloc_string( a1, a2 );

		flogin( user, hash );

		free( user );
		free( hash );
	}

	action return_ftoken {
		char *user = alloc_string( u1, u2 );
		char *hash = alloc_string( a1, a2 );
		char *reqid = alloc_string( r1, r2 );

		return_ftoken( user, hash, reqid );

		free( user );
		free( hash );
		free( reqid );
	}

	action fetch_ftoken {
		char *reqid = alloc_string( r1, r2 );
		fetch_ftoken( reqid );
		free( reqid );
	}

	action set_config {
		char *identity = alloc_string( i1, i2 );
		set_config_by_uri( identity );
		free( identity );
	}

	action session_key {
		char *user = alloc_string( u1, u2 );
		char *identity = alloc_string( i1, i2 );
		char *enc = alloc_string( e1, e2 );
		char *sig = alloc_string( s1, s2 );
		char *generation = alloc_string( g1, g2 );

		session_key( user, identity, enc, sig, generation );

		free( user );
		free( identity );
		free( enc );
		free( sig );
		free( generation );
	}

	action forward_to {
		char *user = alloc_string( u1, u2 );
		char *identity = alloc_string( i1, i2 );
		char *number = alloc_string( n1, n2 );
		char *identity2 = alloc_string( j1, j2 );

		forward_to( user, identity, number, identity2 );

		free( user );
		free( identity );
		free( number );
		free( identity2 );
	}

	commands := |* 
		# Admin commands.
		'new_user'i ' ' comm_key ' ' user ' ' pass ' ' email EOL @new_user;

		# Public key sharing.
		'public_key'i ' ' user EOL @public_key;

		# Friend Requests.
		'friend_req'i ' ' user ' ' identity EOL @friend_req;
		'fetch_fr_relid'i ' ' reqid EOL @fetch_fr_relid;
		'return_relid'i ' ' user ' ' reqid ' ' identity EOL @return_relid;
		'fetch_relid'i ' ' reqid EOL @fetch_relid;
		'friend_final'i ' ' user ' ' reqid ' ' identity EOL @friend_final;

		# Friend Request Accept
		'accept_friend'i ' ' comm_key ' ' user ' ' reqid EOL @accept_friend;

		# Friend login. 
		'flogin'i ' ' user ' ' hash EOL @flogin;
		'return_ftoken'i ' ' user ' ' hash ' ' reqid EOL @return_ftoken;
		'fetch_ftoken'i ' ' reqid EOL @fetch_ftoken;

		# Message Sending
		'session_key'i ' ' user ' ' identity ' ' enc ' ' sig ' ' generation EOL @session_key;
		'forward_to'i ' ' user ' ' identity ' ' num ' ' identity2  EOL @forward_to;

		'message'i EOL @{ printf("OK\r\n"); fflush(stdout); };
	*|;

	main := 'SPP/0.1'i ' ' identity %set_config EOL @{ fgoto commands; };
}%%

%% write data;

const long linelen = 1024;

int server_parse_loop()
{
	long cs, act;
	const char *k1, *k2;
	const char *ts, *te;
	const char *u1, *u2;
	const char *p1, *p2;
	const char *e1, *e2;
	const char *i1, *i2;
	const char *j1, *j2;
	const char *h1, *h2;
	const char *pp1, *pp2;
	const char *r1, *r2;
	const char *a1, *a2;
	const char *s1, *s2;
	const char *g1, *g2;
	const char *n1, *n2;

	%% write init;

	while ( true ) {
		static char buf[linelen];
		char *result = fgets( buf, linelen, stdin );

		/* Just break when client closes the connection. */
		if ( feof( stdin ) )
			break;

		/* Check for an error in the fgets. */
		if ( ! result )
			return -1;

		/* Did we get a full line? */
		long length = strlen( buf );
		if ( buf[length-1] != '\n' )
			return ERR_LINE_TOO_LONG;

		const char *p = buf, *pe = buf + length;

		%% write exec;

		if ( cs < %%{ write first_final; }%% ) {
			if ( cs == parser_error )
				return ERR_PARSE_ERROR;
			else
				return ERR_UNEXPECTED_END;
		}
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
	static char buf[1024];
	long result = 0, cs;
	const char *p, *pe;
	const char *n1, *n2, *e1, *e2;
	bool OK = false;

	long socketFd = open_inet_connection( host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	/* Send the request. */
	FILE *writeSocket = fdopen( socketFd, "w" );
	fprintf( writeSocket, "SPP/0.1 %s\r\npublic_key %s\r\n", site, user );
	fflush( writeSocket );

	/* Read the result. */
	FILE *readSocket = fdopen( socketFd, "r" );
	char *readRes = fgets( buf, 1024, readSocket );

	/* If there was an error then fail the fetch. */
	if ( !readRes ) {
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
	fclose( writeSocket );
	fclose( readSocket );
	::close( socketFd );
	return result;
}

/*
 * fetch_fr_relid_net
 */

%%{
	machine fr_relid;
	write data;
}%%


long fetch_fr_relid_net( RelidEncSig &encsig, const char *site, 
		const char *host, const char *fr_reqid )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	const char *e1, *e2, *s1, *s2;
	bool OK = false;

	long socketFd = open_inet_connection( host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	/* Send the request. */
	FILE *writeSocket = fdopen( socketFd, "w" );
	fprintf( writeSocket, "SPP/0.1 %s\r\nfetch_fr_relid %s\r\n", site, fr_reqid );
	fflush( writeSocket );

	/* Read the result. */
	FILE *readSocket = fdopen( socketFd, "r" );
	char *readRes = fgets( buf, 8192, readSocket );

	/* If there was an error then fail the fetch. */
	if ( !readRes ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		EOL = '\r'? '\n';
		include common;

		main := 
			'OK ' enc ' ' sig EOL @{ OK = true; } |
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
	
	encsig.enc = (char*)malloc( e2-e1+1 );
	encsig.sig = (char*)malloc( s2-s1+1 );
	memcpy( encsig.enc, e1, e2-e1 );
	memcpy( encsig.sig, s1, s2-s1 );
	encsig.enc[e2-e1] = 0;
	encsig.sig[s2-s1] = 0;

fail:
	fclose( writeSocket );
	fclose( readSocket );
	::close( socketFd );
	return result;
}


/*
 * fetch_relid_net
 */

%%{
	machine relid;
	write data;
}%%

long fetch_relid_net( RelidEncSig &encsig, const char *site,
		const char *host, const char *reqid )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	const char *e1, *e2, *s1, *s2;
	bool OK = false;

	long socketFd = open_inet_connection( host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	/* Send the request. */
	FILE *writeSocket = fdopen( socketFd, "w" );
	fprintf( writeSocket, "SPP/0.1 %s\r\nfetch_relid %s\r\n", site, reqid );
	fflush( writeSocket );

	/* Read the result. */
	FILE *readSocket = fdopen( socketFd, "r" );
	char *readRes = fgets( buf, 8192, readSocket );

	/* If there was an error then fail the fetch. */
	if ( !readRes ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		EOL = '\r'? '\n';

		enc = [0-9a-f]+      >{e1 = p;} %{e2 = p;};
		sig = [0-9a-f]+      >{s1 = p;} %{s2 = p;};

		main := 
			'OK ' enc ' ' sig EOL @{ OK = true; } |
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
	
	encsig.enc = (char*)malloc( e2-e1+1 );
	encsig.sig = (char*)malloc( s2-s1+1 );
	memcpy( encsig.enc, e1, e2-e1 );
	memcpy( encsig.sig, s1, s2-s1 );
	encsig.enc[e2-e1] = 0;
	encsig.sig[s2-s1] = 0;

fail:
	fclose( writeSocket );
	fclose( readSocket );
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
	const char *e1, *e2, *s1, *s2;
	bool OK = false;

	long socketFd = open_inet_connection( host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	/* Send the request. */
	FILE *writeSocket = fdopen( socketFd, "w" );
	fprintf( writeSocket, "SPP/0.1 %s\r\nfetch_ftoken %s\r\n", site, flogin_reqid );
	fflush( writeSocket );

	/* Read the result. */
	FILE *readSocket = fdopen( socketFd, "r" );
	char *readRes = fgets( buf, 8192, readSocket );

	/* If there was an error then fail the fetch. */
	if ( !readRes ) {
		result = ERR_READ_ERROR;
		goto fail;
	}

	/* Parser for response. */
	%%{
		EOL = '\r'? '\n';

		enc = [0-9a-f]+      >{e1 = p;} %{e2 = p;};
		sig = [0-9a-f]+      >{s1 = p;} %{s2 = p;};

		main := 
			'OK ' enc ' ' sig EOL @{ OK = true; } |
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
	
	encsig.enc = (char*)malloc( e2-e1+1 );
	encsig.sig = (char*)malloc( s2-s1+1 );
	memcpy( encsig.enc, e1, e2-e1 );
	memcpy( encsig.sig, s1, s2-s1 );
	encsig.enc[e2-e1] = 0;
	encsig.sig[s2-s1] = 0;

fail:
	fclose( writeSocket );
	fclose( readSocket );
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
 * send_message
 */

%%{
	machine send_message;
	write data;
}%%

long send_message( const char *from, const char *to, const char *message )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	bool OK = false;
	long pres;

	/* Need to parse the identity. */
	Identity toIdent( to );
	pres = toIdent.parse();

	if ( pres < 0 )
		return pres;

	long socketFd = open_inet_connection( toIdent.host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	/* Send the request. */
	FILE *writeSocket = fdopen( socketFd, "w" );
	fprintf( writeSocket, "SPP/0.1 %s\r\nmessage\r\n", toIdent.site );
	fflush( writeSocket );

	/* Read the result. */
	FILE *readSocket = fdopen( socketFd, "r" );
	char *readRes = fgets( buf, 8192, readSocket );

	/* If there was an error then fail the fetch. */
	if ( !readRes ) {
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
	fclose( writeSocket );
	fclose( readSocket );
	::close( socketFd );
	return result;
}

/*
 * send_session_key
 */

%%{
	machine send_session_key;
	write data;
}%%

long send_session_key( const char *from, const char *to, const char *enc,
	const char *sig, long long generation )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	bool OK = false;
	long pres;

	/* Need to parse the identity. */
	Identity toIdent( to );
	pres = toIdent.parse();

	if ( pres < 0 )
		return pres;

	long socketFd = open_inet_connection( toIdent.host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	/* Send the request. */
	FILE *writeSocket = fdopen( socketFd, "w" );
	fprintf( writeSocket,
		"SPP/0.1 %s\r\n"
		"session_key %s %s%s/ %s %s %lld\r\n", 
		toIdent.site, toIdent.user, c->CFG_URI, from, enc, sig, generation );
	fflush( writeSocket );

	/* Read the result. */
	FILE *readSocket = fdopen( socketFd, "r" );
	char *readRes = fgets( buf, 8192, readSocket );

//	printf( "send_session_key result: %s\n", readRes );

	/* If there was an error then fail the fetch. */
	if ( !readRes ) {
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
	fclose( writeSocket );
	fclose( readSocket );
	::close( socketFd );
	return result;
}

/*
 * send_session_key
 */

%%{
	machine send_forward_to;
	write data;
}%%

long send_forward_to( const char *from, const char *to, int childNum, const char *forwardTo )
{
	static char buf[8192];
	long result = 0, cs;
	const char *p, *pe;
	bool OK = false;
	long pres;

	/* Need to parse the identity. */
	Identity toIdent( to );
	pres = toIdent.parse();

	if ( pres < 0 )
		return pres;

	long socketFd = open_inet_connection( toIdent.host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		return ERR_CONNECTION_FAILED;

	/* Send the request. */
	FILE *writeSocket = fdopen( socketFd, "w" );
	fprintf( writeSocket, 
		"SPP/0.1 %s\r\n" 
		"forward_to %s %s%s/ %d %s\r\n", 
		toIdent.site, 
		toIdent.user, c->CFG_URI, from, childNum, forwardTo );
	fflush( writeSocket );


	/* Read the result. */
	FILE *readSocket = fdopen( socketFd, "r" );
	char *readRes = fgets( buf, 8192, readSocket );

	/* If there was an error then fail the fetch. */
	if ( !readRes ) {
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
	fclose( writeSocket );
	fclose( readSocket );
	::close( socketFd );
	return result;
}

