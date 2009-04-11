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

#ifndef _SPPD_H
#define _SPPD_H

#include <mysql.h>

struct PublicKey
{
	char *n;
	char *e;
};

struct RelidEncSig
{
	char *enc;
	char *sig;
};

struct Identity
{
	Identity( const char *identity ) :
		identity(identity), 
		host(0), user(0), site(0) {}

	Identity() :
		identity(0), 
		host(0), user(0), site(0) {}

	long parse();

	const char *identity;
	const char *host;
	const char *user;
	const char *site;
};

void run_queue( const char *siteName );
int server_parse_loop();
int rcfile_parse( const char *data, long length );

/* Commands. */
void new_user( const char *key, const char *user, const char *pass, const char *email );
void public_key( const char *identity );
void friend_req( const char *user, const char *identity );
void fetch_fr_relid( const char *reqid );
void return_relid( const char *user, const char *fr_reqid_str, 
		const char *identity, const char *id_host, const char *id_user );
void fetch_relid( const char *reqid );
void friend_final( const char *user, const char *reqid, 
		const char *identity, const char *id_host, const char *id_user );
void accept_friend( const char *key, const char *user, const char *user_reqid );
void flogin( const char *user, const char *hash );
void return_ftoken( const char *user, const char *hash, const char *flogin_reqid_str );
void fetch_ftoken( const char *reqid );
void set_config_by_uri( const char *uri );
void set_config_by_name( const char *name );
void session_key( const char *user, const char *identity, const char *enc,
		const char *sig, const char *generation );

void forward_to( const char *user, const char *identity,
		const char *number, const char *identity2 );

long fetch_public_key_net( PublicKey &pub, const char *site,
		const char *host, const char *user );
long open_inet_connection( const char *hostname, unsigned short port );
long fetch_fr_relid_net( RelidEncSig &encsig, const char *site,
		const char *host, const char *fr_reqid );
long fetch_relid_net( RelidEncSig &encsig, const char *site, 
		const char *host, const char *reqid );
long fetch_ftoken_net( RelidEncSig &encsig, const char *site,
		const char *host, const char *flogin_reqid );
char *get_site( const char *identity );

long send_message( const char *from, const char *to, const char *message );
long send_session_key( const char *from, const char *to, const char *enc,
		const char *sig, long long generation );
long send_forward_to( const char *from, const char *to, int childNum, const char *forwardTo );

struct Config
{
	/* NOTE: must be mirrored by the cfgVals array. */
	char *CFG_URI;
	char *CFG_HOST;
	char *CFG_PATH;
	char *CFG_DB_HOST;
	char *CFG_DB_DATABASE;
	char *CFG_DB_USER;
	char *CFG_ADMIN_PASS;
	char *CFG_COMM_KEY;
	char *CFG_PORT;

	char *name;
	Config *next;
};

extern Config *c, *config_first, *config_last;

#define ERR_READ_ERROR         -1
#define ERR_LINE_TOO_LONG      -2
#define ERR_PARSE_ERROR        -3
#define ERR_UNEXPECTED_END     -4
#define ERR_CONNECTION_FAILED  -5
#define ERR_SERVER_ERROR       -6
#define ERR_SOCKET_ALLOC       -7
#define ERR_RESOLVING_NAME     -8
#define ERR_CONNECTING         -9
#define ERR_QUERY_ERROR        -10

#define RELID_SIZE 16
#define REQID_SIZE 16

char *bin2hex( unsigned char *data, long len );
long hex2bin( unsigned char *dest, long len, const char *src );

int exec_query( MYSQL *mysql, const char *fmt, ... );

#endif
