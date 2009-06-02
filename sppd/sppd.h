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

	void load( const char *identity )
		{ this->identity = identity; }

	long parse();

	const char *identity;
	const char *host;
	const char *user;
	const char *site;
};

void run_queue( const char *siteName );
long run_broadcast_queue_db( MYSQL *mysql );
long run_message_queue_db( MYSQL *mysql );
int server_parse_loop();
int rcfile_parse( const char *data, long length );

/* Commands. */
void new_user( MYSQL *mysql, const char *user, const char *pass, const char *email );
void public_key( MYSQL *mysql, const char *identity );
void relid_request( MYSQL *mysql, const char *user, const char *identity );
void fetch_requested_relid( MYSQL *mysql, const char *reqid );
void relid_response( MYSQL *mysql, const char *user, const char *fr_reqid_str, 
		const char *identity, const char *id_host, const char *id_user );
void fetch_response_relid( MYSQL *mysql, const char *reqid );
void friend_final( MYSQL *mysql, const char *user, const char *reqid, 
		const char *identity, const char *id_host, const char *id_user );
void accept_friend( MYSQL *mysql, const char *user, const char *user_reqid );
void ftoken_request( MYSQL *mysql, const char *user, const char *hash );
void ftoken_response( MYSQL *mysql, const char *user, const char *hash, 
		const char *flogin_reqid_str );
void fetch_ftoken( MYSQL *mysql, const char *reqid );
void set_config_by_uri( const char *uri );
void set_config_by_name( const char *name );
void session_key( MYSQL *mysql, const char *relid, const char *user, const char *identity,
		const char *sk, const char *generation );

void forward_to( MYSQL *mysql, const char *user, const char *identity,
		const char *number, const char *relid, const char *to_identity );

long fetch_public_key_net( PublicKey &pub, const char *site,
		const char *host, const char *user );
long open_inet_connection( const char *hostname, unsigned short port );
long fetch_requested_relid_net( RelidEncSig &encsig, const char *site,
		const char *host, const char *fr_reqid );
long fetch_response_relid_net( RelidEncSig &encsig, const char *site, 
		const char *host, const char *reqid );
long fetch_ftoken_net( RelidEncSig &encsig, const char *site,
		const char *host, const char *flogin_reqid );
char *get_site( const char *identity );

long queue_broadcast( MYSQL *mysql, const char *user, const char *hash,
		const char *sig2, long long generation2, const char *message );
long send_broadcast_net( const char *toSite, const char *relid, const char *hash,
		const char *sig1, const char *sig2, long long generation1, long long generation2,
		const char *message );
long send_session_key( MYSQL *mysql, const char *from_user, const char *to_identity, 
		const char *session_key, long long generation );
long send_forward_to( MYSQL *mysql, const char *from, const char *to, int childNum, 
		const char *forwardToSite, const char *relid );
void forward_tree_insert( MYSQL *mysql, const char *user, const char *identity, const char *relid );
void broadcast( MYSQL *mysql, const char *relid, const char *hash,
		const char *sig1, const char *sig2, long long generation1, long long generation2, 
		const char *message );

void receive_message( MYSQL *mysql, const char *relid,
		const char *enc, const char *sig, const char *message );
long queue_broadcast_db( MYSQL *mysql, const char *to_site, const char *relid,
		const char *hash, const char *sig1, const char *sig2,
		long long generation1, long long generation2, const char *message );
long send_message_net( const char *to_identity, const char *relid,
		const char *enc, const char *sig, const char *message );
long queue_message( MYSQL *mysql, const char *from_user,
		const char *to_identity, const char *message );
void submit_ftoken( MYSQL *mysql, const char *token );
void remote_publish( MYSQL *mysql, const char *user,
		const char *identity, const char *token,
		long len, const char *user_message );

bool check_comm_key( const char *key );

long submit_broadcast( MYSQL *mysql, const char *user, const char *user_message );
long submit_remote_broadcast( MYSQL *mysql, const char *user, 
		const char *identity, const char *token, const char *user_message );
long send_remote_publish_net( char *&resultEnc, char *&resultSig, long long &resultGen,
		const char *to_identity, const char *from_identity,
		const char *token, const char *message );

/* Note: decrypted will be written to. */
int store_message( MYSQL *mysql, const char *relid, char *decrypted );

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
extern bool gblKeySubmitted;

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

#define RELID_SIZE  16
#define REQID_SIZE  16
#define TOKEN_SIZE  16
#define SK_SIZE     16
#define SK_SIZE_HEX 33

char *bin2hex( unsigned char *data, long len );
long hex2bin( unsigned char *dest, long len, const char *src );

int exec_query( MYSQL *mysql, const char *fmt, ... );
int message_parser( MYSQL *mysql, const char *relid,
		const char *user, const char *from_user, const char *message );

void login( MYSQL *mysql, const char *user, const char *pass );

MYSQL *db_connect();

void error( const char *fmt, ... );
void warning( const char *fmt, ... );
void message( const char *fmt, ... );
void fatal( const char *fmt, ... );
void openLogFile();

#define ERROR_FRIEND_CLAIM_EXISTS       1
#define ERROR_FRIEND_REQUEST_EXISTS     2
#define ERROR_PUBLIC_KEY                3
#define ERROR_FETCH_REQUESTED_RELID     4
#define ERROR_DECRYPT_VERIFY            5
#define ERROR_ENCRYPT_SIGN              6
#define ERROR_DECRYPTED_SIZE            7
#define ERROR_FETCH_RESPONSE_RELID      8
#define ERROR_REQUESTED_RELID_MATCH     9
#define ERROR_FETCH_FTOKEN             10
#define ERROR_NOT_A_FRIEND             11
#define ERROR_NO_FTOKEN                12
#define ERROR_DB_ERROR                 13

#endif
