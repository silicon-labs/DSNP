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

#ifndef _DSNPD_H
#define _DSNPD_H

#include <mysql.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <list>
#include <string>

#include "string.h"

struct PublicKey
{
	char *n;
	char *e;
};

struct RelidEncSig
{
	char *enc;
	char *sig;
	char *sym;
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

void runQueue( const char *siteName );
long runBroadcastQueue();
long runMessageQueue();

int serverParseLoop();
int rcfile_parse( const char *data, long length );

struct Global
{
	Global()
	:
		configFile(0),
		siteName(0),
		runQueue(false),
		test(false),
		pid(0)
	{}
		
	const char *configFile;
	const char *siteName;
	bool runQueue;
	bool test;
	pid_t pid;
};

extern Global gbl;

/* Commands. */
void newUser( MYSQL *mysql, const char *user, const char *pass, const char *email );
void public_key( MYSQL *mysql, const char *identity );
void relid_request( MYSQL *mysql, const char *user, const char *identity );
void fetch_requested_relid( MYSQL *mysql, const char *reqid );
void relid_response( MYSQL *mysql, const char *user, const char *fr_reqid_str, const char *identity );
void fetch_response_relid( MYSQL *mysql, const char *reqid );
void friend_final( MYSQL *mysql, const char *user, const char *reqid, const char *identity );
void accept_friend( MYSQL *mysql, const char *user, const char *user_reqid );
void ftoken_request( MYSQL *mysql, const char *user, const char *hash );
void ftoken_response( MYSQL *mysql, const char *user, const char *hash, 
		const char *flogin_reqid_str );
void fetch_ftoken( MYSQL *mysql, const char *reqid );
void setConfigByUri( const char *uri );
void setConfigByName( const char *name );
void storeBroadcastKey( MYSQL *mysql, long long friend_claim_id, 
		long long generation, const char *broadcastKey, const char *friendProof );

void forwardTo( MYSQL *mysql, long long friend_claim_id, const char *user, const char *identity,
		int child_num, long long generation, const char *relid, const char *to_identity );

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

long send_forward_to( MYSQL *mysql, const char *from_user, const char *to_id, int childNum, 
		long long generation, const char *forwardToSite, const char *relid );

struct CurrentPutKey
{
	CurrentPutKey( MYSQL *mysql, const char *user );

	long long keyGen;
	String broadcastKey;
	long long treeGenLow;
	long long treeGenHigh;
};

void receiveMessage( MYSQL *mysql, const char *relid, const char *message );
long send_message_net( MYSQL *mysql, bool prefriend, 
		const char *from_user, const char *to_identity, const char *relid,
		const char *message, long mLen, char **result_message );
long send_message_now( MYSQL *mysql, bool prefriend, const char *from_user,
		const char *to_identity, const char *put_relid,
		const char *msg, char **result_msg );
long queueMessage( MYSQL *mysql, const char *from_user,
		const char *to_identity, const char *message );
void submit_ftoken( MYSQL *mysql, const char *token );
void encrypt_remote_broadcast( MYSQL *mysql, const char *user,
		const char *identity, const char *token,
		long long seq_num, const char *msg );
char *decrypt_result( MYSQL *mysql, const char *from_user, 
		const char *to_identity, const char *user_message );
void prefriend_message( MYSQL *mysql, const char *relid, const char *message );
long notify_accept( MYSQL *mysql, const char *for_user, const char *from_id,
		const char *id_salt, const char *requested_relid, const char *returned_relid );
long registered( MYSQL *mysql, const char *for_user, const char *from_id,
		const char *requested_relid, const char *returned_relid );

long submitMessage( MYSQL *mysql, const char *user, const char *toIdentity, const char *msg, long mLen );
long submitBroadcast( MYSQL *mysql, const char *user, const char *msg, long mLen );
long remote_broadcast_request( MYSQL *mysql, const char *user, 
		const char *identity, const char *hash, const char *token,
		const char *user_message, long mLen );

void remote_inner( MYSQL *mysql, const char *user, const char *subject_id, const char *author_id,
               long long seq_num, const char *date, const char *msg, long mLen );
void friend_proof( MYSQL *mysql, const char *user, const char *subject_id, const char *author_id,
		long long seq_num, const char *date );
int remote_broadcast_parser( MYSQL *mysql, const char *user, 
		const char *friend_id, const char *author_id, const char *msg, long mLen );

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
	char *CFG_TLS_CRT;
	char *CFG_TLS_KEY;
	char *CFG_TLS_CA_CERTS;
	char *CFG_NOTIFICATION;

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
#define SALT_SIZE   18

#define MAX_BRD_PHOTO_SIZE 16384

char *bin2hex( unsigned char *data, long len );
long hex2bin( unsigned char *dest, long len, const char *src );

int exec_query( MYSQL *mysql, const char *fmt, ... );
int message_parser( MYSQL *mysql, const char *relid,
		long long friend_claim_id, const char *user, const char *from_user, const char *message );
int prefriend_message_parser( MYSQL *mysql, const char *relid,
		const char *user, const char *friend_id, const char *message );

void login( MYSQL *mysql, const char *user, const char *pass );

MYSQL *dbConnect();

void fatal( const char *fmt, ... );
void error( const char *fmt, ... );
void warning( const char *fmt, ... );
void message( const char *fmt, ... );
void debug( const char *fmt, ... );
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
#define ERROR_FRIEND_OURSELVES         14

extern BIO *bioIn;
extern BIO *bioOut;
BIO *sslStartClient( BIO *readBio, BIO *writeBio, const char *host );
BIO *sslStartServer( BIO *readBio, BIO *writeBio );
void sslInitClient();
void sslInitServer();
void start_tls();
long base64_to_bin( unsigned char *out, long len, const char *src );
AllocString bin_to_base64( const u_char *data, long len );
AllocString bn_to_base64( const BIGNUM *n );

struct DbQuery
{
	DbQuery( MYSQL *mysql, const char *fmt, ... );
	~DbQuery();

	MYSQL_ROW fetchRow()
		{ return mysql_fetch_row( result ); }
	long rows()
		{ return mysql_num_rows( result ); }
	long affectedRows()
		{ return mysql_affected_rows( mysql ); }
	void seek( unsigned long long offset )
		{ mysql_data_seek( result, offset ); }
	
	void free();

	MYSQL *mysql;
	MYSQL_RES *result;
};

long long lastInsertId( MYSQL *mysql );

struct TlsConnect
{
	int connect( const char *host, const char *site );
	BIO *sbio;
};


int notify_accept_result_parser( MYSQL *mysql, const char *user, const char *user_reqid, 
		const char *from_id, const char *requested_relid, const char *returned_relid, const char *msg );
void notify_accept_returned_id_salt( MYSQL *mysql, const char *user, const char *user_reqid, 
		const char *from_id, const char *requested_relid, 
		const char *returned_relid, const char *returned_id_salt );

int forward_tree_swap( MYSQL *mysql, const char *user, const char *id1, const char *id2 );

void app_notification( const char *args, const char *data, long length );

void remote_broadcast_response( MYSQL *mysql, const char *user, const char *reqid );
void remoteBroadcastFinal( MYSQL *mysql, const char *user, const char *nonce );
void return_remote_broadcast( MYSQL *mysql, const char *user, 
		const char *friend_id, const char *nonce, long long generation, const char *sym );

void friendProofRequest( MYSQL *mysql, const char *user, const char *friend_id );
int obtainFriendProof( MYSQL *mysql, const char *user, const char *friend_id );

struct EncryptedBroadcastParser
{
	enum Type
	{
		Unknown = 1,
		RemoteInner,
		FriendProof
	};

	Type type;
	String sym;
	long long generation;

	long parse( const char *msg );
};

struct RemoteBroadcastParser
{
	enum Type
	{
		Unknown = 1,
		RemoteInner,
		FriendProof
	};

	Type type;
	long long seq_num;
	long length;
	String date;
	const char *embeddedMsg;

	int parse( const char *msg, long mLen );
};

struct BroadcastParser
{
	enum Type
	{
		Unknown = 1,
		Direct,
		Remote
	};

	Type type;
	String date, hash;
	long long generation, seq_num;
	long length;
	const char *embeddedMsg;

	int parse( const char *msg, long mLen );
};

struct MessageParser
{
	enum Type
	{
		Unknown = 1,
		BroadcastKey,
		ForwardTo,
		EncryptRemoteBroadcast,
		ReturnRemoteBroadcast,
		FriendProofRequest,
		FriendProof,
		UserMessage
	};

	Type type;

	String identity, number_str, key, relid;
	String sym, token, reqid, hash;
	String date;
	long length, number;
	long long seq_num, generation;
	const char *containedMsg;

	int parse( const char *smg, long mLen );
};

struct PrefriendParser
{
	enum Type
	{
		Unknown = 1,
		NotifyAccept,
		Registered
	};

	Type type;
	String id_salt, requested_relid, returned_relid;
	long long generation;
	String key, sym;

	int parse( const char *msg, long mLen );
};

struct NotifyAcceptResultParser
{
	enum Type
	{
		Unknown = 1,
		NotifyAcceptResult
	};

	Type type;
	String token;
	long long generation;
	String key, sym;

	int parse( const char *msg, long mLen );
};


RSA *fetch_public_key( MYSQL *mysql, const char *identity );
RSA *load_key( MYSQL *mysql, const char *user );
long sendMessageNow( MYSQL *mysql, bool prefriend, const char *from_user,
		const char *to_identity, const char *put_relid,
		const char *msg, char **result_msg );
int friendProof( MYSQL *mysql, const char *user, const char *friend_id,
		const char *hash, long long generation, const char *sym );

long long storeFriendClaim( MYSQL *mysql, const char *user, 
		const char *identity, const char *id_salt, const char *put_relid, 
		const char *get_relid );

AllocString make_id_hash( const char *salt, const char *identity );
long queueBroadcast( MYSQL *mysql, const char *user, const char *msg, long mLen );

void addGroup( MYSQL *mysql, const char *user, const char *group );
void addToGroup( MYSQL *mysql, const char *user, const char *group, const char *identity );

typedef std::list<std::string> RecipientList;

void broadcastReceipient( MYSQL *mysql, RecipientList &recipientList, const char *relid );
void receiveBroadcast( MYSQL *mysql, RecipientList &recipientList, long long keyGen,
		bool forward, long long treeGenLow, long long treeGenHigh, const char *encrypted ); 
long sendBroadcastNet( MYSQL *mysql, const char *toSite, RecipientList &recipients,
		long long keyGen, bool forward, long long treeGenLow, long long treeGenHigh,
		const char *msg, long mLen );

#endif
