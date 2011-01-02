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

#include <mysql/mysql.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <list>
#include <string>

#include "string.h"

#define REL_TYPE_SELF    1
#define REL_TYPE_FRIEND  8

#define NET_TYPE_PRIMARY 1
#define NET_TYPE_GROUP   2

/* Wraps up RSA struct and private key/x509. Useful for transition to CMS. */
struct Keys
{
	RSA *rsa;
};

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


struct IdentityOrig
{
	IdentityOrig( const char *identity ) :
		identity(identity),
		haveId(false)
	{}

	IdentityOrig() {}

	void load( const char *identity )
		{ this->identity = identity; }

	long parse();

	const char *identity;
	const char *host;
	const char *user;
	const char *site;

	long long fetchId( MYSQL *mysql );

private:
	bool haveId;
	long long id;
};

struct User
{
	User( MYSQL *mysql, const char *user );
	User( MYSQL *mysql, long long _id );
	
	long long id();
	
	MYSQL *mysql;
	String user;

	bool haveId;
	long long _id;
};

struct Identity
{
	struct ByHash {};

	Identity( MYSQL *mysql, const char *iduri );
	Identity( MYSQL *mysql, ByHash, const char *hash );
	Identity( MYSQL *mysql, long long _id );

	MYSQL *mysql;
	String iduri;

	long long id();
	AllocString hash();

	const char *host();
	const char *user();
	const char *site();

	Keys *fetchPublicKey();

private:
	long parse();

	String _host;
	String _user;
	String _site;

	bool haveId, parsed;
	long long _id;
};

struct Relationship
{
	Relationship( MYSQL *mysql, User &user, int type, Identity &identity );

	long long id();

	MYSQL *mysql;
	long long user_id;
	int type;
	long long identity_id;
	String defaultName;

private:
	bool haveId;
	long long _id;
};

struct FriendClaim
{
	FriendClaim( MYSQL *mysql, User &user, Identity &identity );
	FriendClaim( MYSQL *mysql, const char *getRelid );

	MYSQL *mysql;

	long long id;
	long long userId;
	long long identityId;
	long long relationshipId;
	String putRelid;
	String getRelid;
};


void runQueue( const char *siteName );
long runBroadcastQueue();
long runMessageQueue();

int serverParseLoop();
int parseRcFile( const char *data, long length );

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
void newUser( MYSQL *mysql, const char *user, const char *pass );
void publicKey( MYSQL *mysql, const char *identity );
void certificate( MYSQL *mysql, const char *identity );
void relidRequest( MYSQL *mysql, const char *user, const char *iduri );
void fetchRequestedRelid( MYSQL *mysql, const char *reqid );
void relidResponse( MYSQL *mysql, const char *user, const char *fr_reqid_str,
		const char *identity );
void fetchResponseRelid( MYSQL *mysql, const char *reqid );
void friendFinal( MYSQL *mysql, const char *user, const char *reqid, const char *identity );
void acceptFriend( MYSQL *mysql, const char *user, const char *user_reqid );
void ftokenRequest( MYSQL *mysql, const char *user, const char *hash );
void ftokenResponse( MYSQL *mysql, const char *user, const char *hash, 
		const char *flogin_reqid_str );
void submitFtoken( MYSQL *mysql, const char *token );
void fetchFtoken( MYSQL *mysql, const char *reqid );
void setConfigByUri( const char *uri );
void setConfigByName( const char *name );
void storeBroadcastKey( MYSQL *mysql, long long friendClaimId, const char *user,
		const char *identity, const char *friendHash, const char *group,
		long long generation, const char *broadcastKey, const char *friendProof1,
		const char *friendProof2 );

void fetchPublicKeyNet( PublicKey &pub, const char *site,
		const char *host, const char *user );
long openInetConnection( const char *hostname, unsigned short port );
long fetch_requested_relid_net( RelidEncSig &encsig, const char *site,
		const char *host, const char *fr_reqid );
long fetch_response_relid_net( RelidEncSig &encsig, const char *site, 
		const char *host, const char *reqid );
long fetch_ftoken_net( RelidEncSig &encsig, const char *site,
		const char *host, const char *flogin_reqid );
char *get_site( const char *identity );

struct CurrentPutKey
{
	CurrentPutKey( MYSQL *mysql, const char *user, const char *group );

	long long networkId;
	long long keyGen;
	String broadcastKey;
};

struct PutKey
{
	PutKey( MYSQL *mysql, long long netorkId );

	String distName;
	long long generation;
	String broadcastKey;
};

void receiveMessage( MYSQL *mysql, const char *relid, const char *message );
long sendMessageNet( MYSQL *mysql, bool prefriend, 
		const char *from_user, const char *to_identity, const char *relid,
		const char *message, long mLen, char **result_message );
long send_message_now( MYSQL *mysql, bool prefriend, const char *from_user,
		const char *to_identity, const char *put_relid,
		const char *msg, char **result_msg );
long queueMessage( MYSQL *mysql, const char *from_user,
		const char *to_identity, const char *msg, long mLen );
void encryptRemoteBroadcast( MYSQL *mysql, const char *user,
		const char *identity, const char *token,
		long long seqNum, const char *group, const char *msg, long mLen );
char *decrypt_result( MYSQL *mysql, const char *from_user, 
		const char *to_identity, const char *user_message );
void prefriendMessage( MYSQL *mysql, const char *relid, const char *message );
long notify_accept( MYSQL *mysql, const char *for_user, const char *from_id,
		const char *id_salt, const char *requested_relid, const char *returned_relid );

long submitMessage( MYSQL *mysql, const char *user, const char *toIdentity, const char *msg, long mLen );
long submitBroadcast( MYSQL *mysql, const char *user, const char *group, const char *msg, long mLen );
long remoteBroadcastRequest( MYSQL *mysql, const char *user, 
		const char *identity, const char *hash, const char *token, const char *group,
		const char *msg, long mLen );

void remoteInner( MYSQL *mysql, const char *user, const char *subject_id, const char *author_id,
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
	char *CFG_DB_PASS;
	char *CFG_COMM_KEY;
	char *CFG_PORT;
	char *CFG_TLS_CRT;
	char *CFG_TLS_KEY;
	char *CFG_TLS_CA_CERTS;

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
void startTls();
long base64ToBin( unsigned char *out, const char *src, long len );
AllocString binToBase64( const u_char *data, long len );
AllocString bnToBase64( const BIGNUM *n );

struct DbQuery
{
	struct Log {};

	DbQuery( MYSQL *mysql, const char *fmt, ... );
	DbQuery( Log, MYSQL *mysql, const char *fmt, ... );
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
	void connect( const char *host, const char *site );
	BIO *sbio;
};


int notify_accept_result_parser( MYSQL *mysql, const char *user, 
		const char *user_reqid, const char *from_id, 
		const char *requested_relid, const char *returned_relid, const char *msg );
void notify_accept_returned_id_salt( MYSQL *mysql, const char *user, 
		const char *user_reqid, const char *from_id, const char *requested_relid, 
		const char *returned_relid, const char *returned_id_salt );

int forward_tree_swap( MYSQL *mysql, const char *user, const char *id1, const char *id2 );

void appNotification( const char *args, const char *data, long length );

void remote_broadcast_response( MYSQL *mysql, const char *user, const char *reqid );
void remoteBroadcastFinal( MYSQL *mysql, const char *user, const char *nonce );
void return_remote_broadcast( MYSQL *mysql, const char *user, 
		const char *friend_id, const char *nonce, long long generation, const char *sym );

void friendProofRequest( MYSQL *mysql, const char *user, const char *friend_id );

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
	String identity1, identity2;

	int parse( const char *msg, long mLen );
};

struct BroadcastParser
{
	enum Type
	{
		Unknown = 1,
		Direct,
		Remote,
		GroupMemberRevocation
	};

	Type type;
	String date, hash, network, identity;
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
		EncryptRemoteBroadcast,
		ReturnRemoteBroadcast,
		FriendProofRequest,
		FriendProof,
		UserMessage
	};

	Type type;

	String identity, number_str, key, relid;
	String sym, token, reqid, hash;
	String date, network, distName, sym1, sym2;
	long length, number;
	long long seq_num, generation;
	const char *embeddedMsg;

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
	String requestedRelid;
	String returnedRelid;

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

Keys *fetchPublicKey( MYSQL *mysql, const char *iduri );
Keys *loadKey( MYSQL *mysql, User &user );
Keys *loadKey( MYSQL *mysql, const char *user );
long sendMessageNow( MYSQL *mysql, bool prefriend, const char *from_user,
		const char *to_identity, const char *put_relid,
		const char *msg, char **result_msg );
int friendProofMessage( MYSQL *mysql, const char *user, const char *friendId,
		const char *hash, const char *group, long long generation, const char *sym );

long long storeFriendClaim( MYSQL *mysql, const char *user, 
		const char *identity, const char *id_salt, const char *put_relid, 
		const char *get_relid );

AllocString makeIdHash( const char *salt, const char *identity );
AllocString makeIduriHash( const char *identity );
long queueBroadcast( MYSQL *mysql, const char *user, const char *group, const char *msg, long mLen );

void showNetwork( MYSQL *mysql, const char *user, const char *network );
void unshowNetwork( MYSQL *mysql, const char *user, const char *network );
void addToNetwork( MYSQL *mysql, const char *user, const char *network, const char *identity );
void addToPrimaryNetwork( MYSQL *mysql, User &user, Identity &identity );
void removeFromNetwork( MYSQL *mysql, const char *user, const char *network, const char *identity );

typedef std::list<std::string> RecipientList;

void broadcastReceipient( MYSQL *mysql, RecipientList &recipientList, const char *relid );
void receiveBroadcast( MYSQL *mysql, RecipientList &recipientList, const char *group,
		long long keyGen, const char *encrypted ); 
long sendBroadcastNet( MYSQL *mysql, const char *toSite, RecipientList &recipients,
		const char *group, long long keyGen, const char *msg, long mLen );
void newBroadcastKey( MYSQL *mysql, long long friendGroupId, long long generation );

long sendRemoteBroadcast( MYSQL *mysql, const char *user,
		const char *authorHash, const char *group, long long generation,
		long long seqNum, const char *encMessage );

void sendAllProofs( MYSQL *mysql, const char *user, const char *group, 
		const char *friendId );
void remoteBroadcast( MYSQL *mysql, const char *user, const char *friendId, 
		const char *hash, const char *network, long long networkId, long long generation,
		const char *msg, long mLen );

long long addNetwork( MYSQL *mysql, long long userId, const char *privateName );

AllocString passHash( const u_char *pass_salt, const char *pass );

void startPreFriend( MYSQL *mysql, char *reqid );

BIGNUM *base64ToBn( const char *base64 );

inline long long parseId( const char *id )
{
	return strtoll( id, 0, 10 );
}

#define LOGIN_TOKEN_LASTS 86400

#endif
