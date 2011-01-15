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

#define RELID_SIZE  16
#define REQID_SIZE  16
#define TOKEN_SIZE  16
#define SK_SIZE     16
#define SK_SIZE_HEX 33
#define SALT_SIZE   18

#define MAX_BRD_PHOTO_SIZE 16384

#define VERSION_MASK_0_1 0x1
#define VERSION_MASK_0_2 0x2

struct BioWrap;
struct TlsConnect;
struct Server;

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
	Identity( long long _id, const char *iduri );

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

struct Parser
{
	enum Control {
		Continue = 1,
		Stop
	};

	virtual Control data( const char *data, int dlen ) = 0;

	/* Run the whole thing at once. */
	void parse( const char *data, int dlen );
};

struct BioWrap
{
	BioWrap();
	~BioWrap();

	int socketFd;

	BIO *rbio;
	BIO *wbio;

	String result;

	const long linelen;
	char *input;

	/* Receiving. */
	int readParse( Parser &parser );

	/* Sending. */
	int printf( const char *fmt, ... );
	void write( const char *msg, long mLen );
	void closeMessage();
};

struct TlsConnect
	: public BioWrap
{
	void connect( const char *host, const char *site );
};

void runQueue( const char *siteName );
long runBroadcastQueue();
long runMessageQueue();

void serverParseLoop( BIO *rbio, BIO *wbio );
int parseRcFile( const char *data, long length );

/* Commands. */
void setConfigByUri( const char *uri );
void setConfigByName( const char *name );
void storeBroadcastKey( MYSQL *mysql, long long friendClaimId, const char *user,
		const char *identity, const char *friendHash, const char *group,
		long long generation, const char *broadcastKey, const char *friendProof1,
		const char *friendProof2 );

void fetchPublicKeyNet( PublicKey &pub, const char *site,
		const char *host, const char *user );
void fetchRequestedRelidNet( RelidEncSig &encsig, const char *site,
		const char *host, const char *fr_reqid );
void fetchResponseRelidNet( RelidEncSig &encsig, const char *site, 
		const char *host, const char *reqid );
void fetchFtokenNet( RelidEncSig &encsig, const char *site,
		const char *host, const char *flogin_reqid );

struct PutKey
{
	PutKey( MYSQL *mysql, long long netorkId );

	String distName;
	long long generation;
	String broadcastKey;
};

void sendMessageNet( MYSQL *mysql, bool prefriend, 
		const char *from_user, const char *to_identity, const char *relid,
		const char *message, long mLen, String &result );
long queueMessage( MYSQL *mysql, const char *from_user,
		const char *to_identity, const char *msg, long mLen );
void encryptRemoteBroadcast( MYSQL *mysql, User &user,
		Identity &identity, const char *token,
		long long seqNum, const char *msg, long mLen );

void remoteInner( MYSQL *mysql, const char *user, const char *subject_id, const char *author_id,
               long long seqNum, const char *date, const char *msg, long mLen );

MYSQL *dbConnect();

void fatal( const char *fmt, ... );
void error( const char *fmt, ... );
void warning( const char *fmt, ... );
void message( const char *fmt, ... );
void debug( const char *fmt, ... );
void openLogFile();

BIO *sslStartClient( BIO *rbio, BIO *wbio, const char *host );
BIO *sslStartServer( BIO *rbio, BIO *wbio );
void sslInitClient();
void sslInitServer();
BIO *startTls( BIO *rbio, BIO *wbio );

/*
 * Conversion
 */

long base64ToBin( unsigned char *out, const char *src, long len );
AllocString binToBase64( const u_char *data, long len );
AllocString bnToBase64( const BIGNUM *n );
char *bin2hex( unsigned char *data, long len );
long hex2bin( unsigned char *dest, long len, const char *src );
AllocString passHash( const u_char *pass_salt, const char *pass );
BIGNUM *base64ToBn( const char *base64 );
long long parseId( const char *id );
long long parseLength( const char *length );

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

typedef std::list<std::string> RecipientList;

struct ServerParser
:
	public Parser
{
	ServerParser();

	virtual Parser::Control data( const char *data, int dlen );

	long cs;
	String user, pass, email, identity; 
	String reqid;
	String hash, key, relid, token, sym;
	String distName;
	long length, counter;
	long long generation;
	int retVal;
	RecipientList recipients;
	Buffer buf;
	String body;

	MYSQL *mysql;
	bool tls;
	bool exit;

	long v, versions;

	Server *server;
};

struct SendMessageParser
:
	public Parser
{
	SendMessageParser();

	virtual Parser::Control data( const char *data, int dlen );

	int cs;
	bool OK;
	bool hasToken;
	Buffer buf;
	String token;
};

struct SendBroadcastRecipientParser
:
	public Parser
{
	SendBroadcastRecipientParser();

	virtual Parser::Control data( const char *data, int dlen );

	int cs;
	bool OK;
};

struct SendBroadcastParser
:
	public Parser
{
	SendBroadcastParser();

	virtual Parser::Control data( const char *data, int dlen );

	int cs;
	bool OK;
};


struct FetchPublicKeyParser
:
	public Parser
{
	FetchPublicKeyParser();
	virtual Parser::Control data( const char *data, int dlen );

	int cs;
	Buffer buf;
	bool OK;
	String n, e;
};

struct FetchRequestedRelidParser
:
	public Parser
{
	FetchRequestedRelidParser();
	virtual Parser::Control data( const char *data, int dlen );

	int cs;
	bool OK;
	Buffer buf;
	String sym;
};

struct FetchResponseRelidParser
:
	public Parser
{
	FetchResponseRelidParser();
	virtual Parser::Control data( const char *data, int dlen );

	int cs;
	bool OK;
	Buffer buf;
	String sym;
};

struct FetchFtokenParser
:
	public Parser
{
	FetchFtokenParser();
	virtual Parser::Control data( const char *data, int dlen );

	int cs;
	bool OK;
	Buffer buf;
	String sym;
};

struct RemoteBroadcastParser
:
	public Parser
{
	enum Type
	{
		Unknown = 1,
		RemoteInner
	};

	Type type;
	long long seqNum;
	long length, counter;
	String date;
	String body;
	String identity1, identity2;

	virtual Control data( const char *data, int dlen );
};

struct BroadcastParser
:
	public Parser
{
	enum Type
	{
		Unknown = 1,
		Direct,
		Remote,
	};

	Type type;
	String date, hash, distName, identity;
	long long generation, seqNum;
	long length, counter;
	String body;

	virtual Control data( const char *data, int dlen );
};

struct MessageParser
:
	public Parser
{
	enum Type
	{
		Unknown = 1,
		BroadcastKey,
		EncryptRemoteBroadcast,
		ReturnRemoteBroadcast,
		UserMessage
	};

	Type type;

	String identity, key, relid;
	String sym, token, reqid, hash;
	String date, distName, sym1, sym2;
	long length, counter, number;
	long long seqNum, generation;
	String body;

	virtual Control data( const char *data, int dlen );
};

struct PrefriendParser
:
	public Parser
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

	virtual Control data( const char *data, int dlen );
};

struct Server
{
	BioWrap *bioWrap;

	void negotiation( long versions, const String &site, bool tls, const String &key );

	void broadcastReceipient( RecipientList &recipients, const char *relid );
	void acceptFriend( const char *user, const char *user_reqid );
	void receiveBroadcast( RecipientList &recipientList, const char *group,
			long long keyGen, const char *encrypted ); 
	void fetchFtoken( const char *reqid );
	void fetchRequestedRelid( const char *reqid );
	void fetchResponseRelid( const char *reqid );
	void friendFinal( const char *user, const char *reqid, const char *identity );
	void ftokenRequest( const char *user, const char *hash );
	void ftokenResponse( const char *user, const char *hash, 
			const char *floginReqid );
	void login( const char *user, const char *pass );
	void receiveMessage( const char *relid, const char *message );
	void newUser( const char *user, const char *pass );
	void prefriendMessage( const char *relid, const char *message );
	void publicKey( const char *identity );
	void relidRequest( const char *user, const char *iduri );
	void relidResponse( const char *user, const char *frReqid,
			const char *identity );
	void remoteBroadcastFinal( const char *user, const char *nonce );
	void remoteBroadcastRequest( const char *user, 
			const char *identity, const char *hash, const char *token,
			const char *msg, long mLen );
	void remoteBroadcastResponse( const char *user, const char *reqid );
	void submitBroadcast( const char *user, const char *msg, long mLen );
	void submitFtoken( const char *token );

	void submitMessage( const char *user, const char *toIdentity, const char *msg, long mLen );


private:
	void notifyAcceptResult( User &user, Identity &identity,
			const char *userReqid, const char *requestedRelid,
			const char *returnedRelid );

	void encryptRemoteBroadcast( User &user,
			Identity &subjectId, const char *token,
			long long seqNum, const char *msg, long mLen );

	void returnRemoteBroadcast( User &user, Identity &identity,
			const char *reqid, const char *network, long long generation,
			const char *sym );

	long registered( User &user, Identity &identity,
			const char *requestedRelid, const char *returnedRelid );

	void remoteBroadcast( User &user, Identity &identity,
			const char *hash, const char *network, long long networkId, long long generation,
			const char *msg, long mLen );

	void storeBroadcastKey( User &user, Identity &identity, FriendClaim &friendClaim,
			const char *distName, long long generation, const char *broadcastKey );

	long notifyAccept( User &user, Identity &identity,
			const String &requestedRelid, const String &returnedRelid );

	void receiveBroadcast( const char *relid, const char *network, 
			long long keyGen, const char *encrypted );

	MYSQL *mysql;
};

void appNotification( const char *args, const char *data, long length );

Keys *loadKey( MYSQL *mysql, User &user );
Keys *loadKey( MYSQL *mysql, const char *user );
void sendMessageNow( MYSQL *mysql, bool prefriend, const char *from_user,
		const char *to_identity, const char *put_relid,
		const char *msg, String &result );
int friendProofMessage( MYSQL *mysql, const char *user, const char *friendId,
		const char *hash, const char *group, long long generation, const char *sym );

long long storeFriendClaim( MYSQL *mysql, const char *user, 
		const char *identity, const char *id_salt, const char *put_relid, 
		const char *get_relid );

AllocString makeIdHash( const char *salt, const char *identity );
AllocString makeIduriHash( const char *identity );
long queueBroadcast( MYSQL *mysql, const char *user, const char *group, const char *msg, long mLen );

void addToPrimaryNetwork( MYSQL *mysql, User &user, Identity &identity );

long sendBroadcastNet( MYSQL *mysql, const char *toHost, const char *toSite,
		RecipientList &recipients, const char *group, long long keyGen, const char *msg, long mLen );
void newBroadcastKey( MYSQL *mysql, long long friendGroupId, long long generation );

long sendRemoteBroadcast( MYSQL *mysql, const char *user,
		const char *authorHash, const char *group, long long generation,
		long long seqNum, const char *encMessage );

void remoteBroadcast( MYSQL *mysql, const char *user, const char *friendId, 
		const char *hash, const char *network, long long networkId, long long generation,
		const char *msg, long mLen );

long long addNetwork( MYSQL *mysql, long long userId, const char *privateName );


long long findPrimaryNetworkId( MYSQL *mysql, User &user );
AllocString findPrimaryNetworkName( MYSQL *mysql, User &user );

#define LOGIN_TOKEN_LASTS 86400

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


#endif
