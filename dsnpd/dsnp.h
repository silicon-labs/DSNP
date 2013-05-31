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
#include <openssl/ssl.h>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "lstring.h"
#include "buffer.h"
#include "parser.h"
#include "dlist.h"
#include "recipients.h"

#define DSNPD_LOG_FILE LOGDIR "/dsnpd.log"
#define DSNPK_LOG_FILE LOGDIR "/dsnpk.log"
#define NOTIF_LOG_FILE LOGDIR "/dsnpn.log"

/* Types of things should never be zero. */
#define INVALID_THING 0

#define REL_TYPE_SELF    1
#define REL_TYPE_FRIEND  8

#define NET_TYPE_PRIMARY 1
#define NET_TYPE_GROUP   2

#define RELID_PREFRIEND  20
#define RELID_MESSAGE    21

#define ACTOR_TYPE_PUBLISHER 70
#define ACTOR_TYPE_AUTHOR    71
#define ACTOR_TYPE_SUBJECT   72

/* For subjects we can go right into completed. But for author we need to go
 * into returned once it comes back and complete only in the final step
 * controlled by the browser. */
#define ACTOR_STATE_PENDING   90
#define ACTOR_STATE_RETURNED  91
#define ACTOR_STATE_COMPLETE  92

#define RB_REQ_STATE_PENDING   40
#define RB_REQ_STATE_COMPLETE  41

#define RB_RSP_STATE_PENDING   50
#define RB_RSP_STATE_COMPLETE  51

#define NUM_KEY_PRIVS 5
#define KEY_PRIV0 0L
#define KEY_PRIV1 1L
#define KEY_PRIV2 2L
#define KEY_PRIV3 3L
#define KEY_PRIV4 4L

#define RELID_SIZE  16
#define REQID_SIZE  16
#define TOKEN_SIZE  16
#define SK_SIZE     16
#define SK_SIZE_HEX 33
#define SALT_SIZE   18

#define MAX_BRD_PHOTO_SIZE 16384

// --VERSION--
#define VERSION_MASK_0_1 0x01
#define VERSION_MASK_0_2 0x02
#define VERSION_MASK_0_3 0x04
#define VERSION_MASK_0_4 0x08
#define VERSION_MASK_0_5 0x10
#define VERSION_MASK_0_6 0x20

#define DAEMON_DAEMON_TIMEOUT 7

#define DSNPD_CONF SYSCONFDIR "/dsnpd.conf"

/* Barrier commands. */
#define BA_QUIT                       11

/* Agent control commands */
#define AC_SOCKET     60
#define AC_LOG_FD     61
#define AC_QUIT       62

#define CHECK_PASS_OK 1
#define CHECK_PASS_BAD_USER 2
#define CHECK_PASS_BAD_PASS 3

#define FC_SENT             40L
#define FC_GRANTED_ACCEPT   41L
#define FC_RECEIVED         42L
#define FC_ESTABLISHED      43L

struct BioWrapParse;
struct TlsConnect;
struct Server;
struct Broadcast;

/* There are a number of SSL context's necessary. There must be a server
 * context for each site that contains the appropriate keys. There can be only
 * one client context, which contains the loaded list of trusted CA certs. */
struct TlsContext
{
	/* Indexed by configuration id. */
	std::vector<SSL_CTX*> clientCtx;
	std::vector<SSL_CTX*> serverCtx;
};

struct ConfigSection;
struct Config;

struct ConfigCtx
{
	ConfigCtx( Config *c ) : c(c) {}

	MYSQL *dbConnect( const String &host, const String &database,
			const String &user, const String &pass );
	MYSQL *dbConnect();

	Config *c;
};


/* Wraps up RSA struct and private key/x509. Useful for transition to CMS. */
struct Keys
{
	RSA *rsa;
};

struct User
{
	struct ByLoginToken {};

	User( MYSQL *mysql, ByLoginToken, const char *loginToken );
	User( MYSQL *mysql, const char *user );
	User( MYSQL *mysql, long long _id );
	
	long long id();
	
	MYSQL *mysql;
	String iduri;

	long long siteId();
	Allocated site();

	bool haveId;
	long long _id;
};

struct Site
{
	struct ByLoginToken {};

	Site( MYSQL *mysql, const char *_site );
	Site( MYSQL *mysql, long long _id );
	
	long long id();
	
	MYSQL *mysql;
	String site;

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
	Allocated hash();
	bool publicKey();

	const char *host();

private:
	long parse();

	String _host;

	bool haveId, havePublicKey, parsed;
	long long _id;
	bool _publicKey;
};

struct FriendClaim
{
	struct ByFloginToken {};

	FriendClaim( MYSQL *mysql, User &user, Identity &identity );
	FriendClaim( MYSQL *mysql, const char *getRelid );
	FriendClaim( MYSQL *mysql, ByFloginToken, const char *floginToken );

	MYSQL *mysql;

	void loadRelids();

	long long id;
	long long userId;
	long long identityId;
	int state;

	String putRelids[NUM_KEY_PRIVS];
	String getRelids[NUM_KEY_PRIVS];
};

struct BioWrap
{
	enum Type
	{
		Null = 1,
		Server,
		Local,
	};

	BioWrap( Type type );

	Type type;
	int sockFd;
	BIO *sockBio;

	/* Sending. */
	int printf( const char *fmt, ... );
	void write( const char *msg, long mLen );
	void write( const String &msg ) 
		{ write( msg.data, msg.length ); }
	void writeBody( const String &msg );

	void returnOkLocal();
	void returnOkLocal( const String &r1 );
	void returnOkLocal( const String &r1, const String &r2 );
	void returnOkLocal( const String &r1, const String &r2, long ld3 );
	void returnOkLocal( const String &r1, const String &r2, const String &r3 );

	void returnOkServer();
	void returnOkServer( const String &r1 );

	void returnError( int errorCode );
	void returnError( int errorCode, int arg1 );
	void returnError( int errorCode, int arg1, int arg2 );
	void returnError( int errorCode, const char *arg1 );
	void returnError( int errorCode, const char *arg1, const char *arg2 );
};

struct BioWrapParse
:
	public ConfigCtx,
	public BioWrap
{
	BioWrapParse( Config *c, BioWrap::Type type, TlsContext &tlsContext );
	~BioWrapParse();

	void setSockFd( int sfd );

	TlsContext &tlsContext;

	String result;

	const long linelen;
	char *input;

	void makeNonBlocking();
	void makeNonBlocking( int fd );

	template <class Func, class Throw> void nonBlockingSslFunc( SSL *ssl );

	/* Receiving. */
	int readParse( Parser &parser );


	void sslError( int e );
	void sslStartServer();
	void startTls();
};

struct TlsConnect
:
	public BioWrapParse
{
	/* This is always a server-server BIO wrap. */
	TlsConnect( Config *c, TlsContext &tlsContext )
	:
		BioWrapParse( c, BioWrap::Server, tlsContext )
	{}

	void connect( const String &host );

private:
	void sslStartClient( const String &host );
	void openInetConnection( const String &host, unsigned short port );
};

enum ConfigSlice
{
	SliceDaemon = 1,
	SliceKeyAgent,
	SliceNotifAgent
};

struct ConfigVar
{
	const char *name;
	ConfigSlice slice;
};

struct ConfigSection
{
	ConfigSection( int id )
		: id(id) {}

	/* Main sections. */
	String CFG_PORT;
	String CFG_DB_HOST;
	String CFG_DB_USER;
	String CFG_DB_DATABASE;
	String CFG_DB_PASS;
	String CFG_KEYS_HOST;
	String CFG_KEYS_USER;
	String CFG_KEYS_DATABASE;
	String CFG_KEYS_PASS;
	String CFG_NOTIF_HOST;
	String CFG_NOTIF_KEYS_USER;
	String CFG_NOTIF_DATABASE;
	String CFG_NOTIF_PASS;

	/* Host sections. */
	String CFG_HOST;
	String CFG_TLS_CRT;
	String CFG_TLS_KEY;

	/* Site sections. */
	String CFG_NOTIFICATION;
	String CFG_COMM_KEY;

	/* Name is given in the config. Id is allocated. */
	String name;
	int id;

	ConfigSection *prev, *next;
};

struct ConfigList
	: public DList<ConfigSection>
{
};

struct Config
{
	Config()
		: main(0), host(0), site(0) {}
	
	/* The main config section from the file. */
	ConfigSection *main;

	/* List of hosts and sites. */
	ConfigList hostList;
	ConfigList siteList;

	/* The selected host and site. */
	ConfigSection *host;
	ConfigSection *site;

	void selectHostByHostName( const String &hostName );
	void selectSiteByCommKey( const String &key );
	void selectSiteByName( const String &site );
};

struct ConfigParser
{
	ConfigParser( const char *confFile, ConfigSlice requestedSlice, Config *config );

	void setValue( int i, const String &value );

	void init();
	void parseData( const char *data, long length );

	void startHost();
	void startSite();
	void processValue();

	String name, value;
	Buffer buf;
	int cs;

	/* output. */
	Config *config;

	/* Parsing context. */
	ConfigSection *curSect;
	int nextConfigSectionId;
	ConfigSlice requestedSlice;

	static ConfigVar varNames[];
};

struct PutKey
{
	PutKey( MYSQL *mysql, long long netorkId );

	String distName;
	long long generation;
	long long id;
};


void fatal( const char *fmt, ... );
void error( const char *fmt, ... );
void warning( const char *fmt, ... );
void message( const char *fmt, ... );
void _dsnpd_debug( long realm, const char *fmt, ... );
int openLogFile( const char *fn );
void openLogFile();
void setLogFd( int fd );
void logToConsole( int fd );

#define DBG_FDT    0x0001
#define DBG_PROC   0x0002
#define DBG_EP     0x0004
#define DBG_PRIV   0x0008
#define DBG_NOTIF  0x0010
#define DBG_CFG    0x0020
#define DBG_QUEUE  0x0040

#if ENABLE_DEBUG
	#define debug( realm, ... ) _dsnpd_debug( realm, __VA_ARGS__ )
#else
	#define debug( realm, ... ) 
#endif


/*
 * Conversion
 */

Allocated base64ToBin( const char *src, long srcLen );
inline Allocated base64ToBin( const String &src ) { return base64ToBin( src(), src.length ); }
Allocated binToBase64( const u_char *data, long len );
inline Allocated binToBase64( const String &src ) { return binToBase64( src.binary(), src.length ); }
Allocated bnToBase64( const BIGNUM *n );
Allocated bnToBin( const BIGNUM *n );
char *bin2hex( unsigned char *data, long len );
long hex2bin( unsigned char *dest, long len, const char *src );
Allocated passHash( const u_char *pass_salt, const char *pass );
BIGNUM *base64ToBn( const char *base64 );
BIGNUM *binToBn( const String &bin );

struct DbQuery
{
	struct Log {};

	DbQuery( MYSQL *mysql, const char *fmt, ... );
	DbQuery( Log, MYSQL *mysql, const char *fmt, ... );
	~DbQuery();

	MYSQL_ROW fetchRow()
		{ return mysql_fetch_row( result ); }
	u_long *fetchLengths()
		{ return mysql_fetch_lengths( result ); }
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


struct ServerParser
:
	public Parser
{
	ServerParser( Server *server );

	virtual Parser::Control data( const char *data, int dlen );

	long cs;
	String user, pass, email, iduri; 
	String reqid;
	String hash, key, relid, token;
	String distName;
	String sessionId;
	String loginToken, floginToken;
	long length, counter;
	long long generation;
	int retVal;
	RecipientList recipientList;
	Buffer buf;
	String body;
	String host;

	MYSQL *mysql;
	bool tls;
	bool exit;
	long v, versions;

	u_long val;
	u_char *dest;

	Server *server;
};

struct CommandParser
:
	public Parser
{
	CommandParser( Server *server );

	virtual Parser::Control data( const char *data, int dlen );

	long cs;
	String user, pass, email, iduri; 
	String reqid;
	String hash, key, relid, token;
	String distName, privateName;
	String sessionId;
	String loginToken, floginToken;
	long length, counter;
	long long generation;
	int retVal;
	RecipientList recipientList;
	Buffer buf;
	String body;
	String host;

	MYSQL *mysql;
	bool tls;
	bool exit;
	long v, versions;

	u_long val;
	u_char *dest;

	Server *server;
};


struct UserMessageParser
:
	public Parser
{
	UserMessageParser( const String &msg )
	{
		parse( msg );
	}

	long cs;
	Buffer buf;
	String messageId;
	String publisher;
	String author;
	SubjectList subjects;

	virtual Control data( const char *data, int dlen );

};

struct ResponseParser
:
	public Parser
{
	ResponseParser();

	virtual Parser::Control data( const char *data, int dlen );

	int cs;
	bool OK;
	Buffer buf;
	String body;
	int length, counter;

	u_long val;
	u_char *dest;
};

struct MessageParser
:
	public Parser
{
	enum Type
	{
		Unknown = 1,
		BroadcastKey,
		RemoteBroadcastKey,
		EncryptRemoteBroadcastAuthor,
		EncryptRemoteBroadcastSubject,
		ReturnRemoteBroadcastAuthor,
		ReturnRemoteBroadcastSubject,
		BroadcastSuccessAuthor,
		BroadcastSuccessSubject,
		UserMessage,
		RepubRemoteBroadcastPublisher,
		RepubRemoteBroadcastAuthor,
		RepubRemoteBroadcastSubject,
	};

	long cs;
	Buffer buf;

	Type type;

	String messageId;
	String iduri, relid;
	String token, reqid, hash;
	String distName;
	long length, counter, number;
	long long generation;
	String body;
	String recipients;

	u_long val;
	u_char *dest;

	virtual Control data( const char *data, int dlen );
};

struct FofMessageParser
:
	public Parser
{
	enum Type
	{
		Unknown = 1,
		FetchRbBroadcastKey,
	};

	long cs;
	Buffer buf;

	Type type;

	long length, counter;
	u_long val;
	u_char *dest;
	long long generation;

	String hash;
	String memberProof;
	String distName;

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

	long cs;
	Buffer buf;

	long counter;
	u_long val;
	u_char *dest;

	Type type;
	String peerNotifyReqid;
	String friendClaimSigKey;

	virtual Control data( const char *data, int dlen );
};

struct Barrier
{
	Barrier( int fd )
		: fd(fd) {}

	char readCommand();
	void command( char cmd );
	void quit();

	char readChar();
	int readInt();
	void readData( String &s );

	long long readLongLong();
	void writeLongLong( long long ll );

	void writeChar( char c );
	void writeInt( int i );
	void writeData( const String &s );

	int fd;
};

struct NotifService
:
	public ConfigCtx,
	public Barrier
{
	NotifService( Config *c, int fd )
	:
		ConfigCtx(c),
		Barrier(fd)
	{}

	int service();
	void recvConfig();

	char *const* makeNotifiyArgv();
	void recvNotification();
	void execNotification( int stdinFd, int stdoutFd, int stderrFd );
	void sendArgsBody( int fd, const String &site, const String &args, const String &body );
	void waitNotification( pid_t pid );
	FILE *wrapPipeFd( int fd, const char *mode );

	int readResult( int fd );
	void writeNotif( int fd, const char *data, long dlen );
};

struct NotifAgent
	: public Barrier
{
	NotifAgent( int fd )
	:
		Barrier(fd)
	{}

	void appNotification( const String &site, const String &args );
	void appNotification( const String &site, const String &args, const String &body );

	void notifNewUser( const String &site, const String &iduri,
			const String &hash, const String &distName );
	void notifLogout( const String &site, const char *sessionId );

	void notifFriendRequestSent( const String &site, const char *user, const char *iuduri,
			const char *hash, const char *userNotifyReqid );
	void notifFriendRequestReceived( const String &site, const char *user,
			const char *iduri, const char *hash, const char *acceptReqid );
	void notifFriendRequestAccepted( const String &site, const char *user, 
			const char *iduri, const char *acceptReqid );
	void notifSentFriendRequestAccepted( const String &site, const char *user, 
			const char *iduri, const char *userNotifyReqid );

	void notifMessage( const String &site, const char *user, const char *friendId, 
			const String &msg );
	void notifBroadcast( const String &site, const char *user, 
			const char *broadcaster, const String &msg );
};

struct KeyAgent;


struct Server
:
	public ConfigCtx
{
	Server( Config *c, TlsContext &tlsContext, KeyAgent &keyAgent, NotifAgent &notifAgent )
	: 
		ConfigCtx(c), 
		tlsContext(tlsContext),
		bioWrap(c, BioWrap::Server, tlsContext),
		keyAgent(keyAgent),
		notifAgent(notifAgent),
		mysql(0)
	{}

	TlsContext &tlsContext;
	BioWrapParse bioWrap;

	KeyAgent &keyAgent;
	NotifAgent &notifAgent;

	bool deliverBroadcast();

	void runServerBare( int sockFd );
	void runServer( int sockFd );

	void runReceivedQueueBare();
	void runReceivedQueue();
	
	void runCommandBare();
	int runCommand();

	void negotiation( long versions, bool tls, const String &host, const String &key );

	void broadcastReceipient( RecipientList &recipients, const String &relid );
	void acceptFriend( const String &token, const String &reqid );
	void receiveBroadcastList( RecipientList &recipientList, const String &distName,
			long long keyGen, const String &msg );
	void fetchFtoken( const String &reqid );
	void fetchRequestedRelid( const String &reqid );
	void fetchResponseRelid( const String &reqid );
	void friendFinal( const String &user, const String &reqid, const String &iduri );
	void login( const String &user, const String &pass, const String &sessionId );
	void ftokenRequest( const String &user, const String &hash );
	void ftokenResponse( const String &user, const String &hash, 
			const String &reqid );
	void submitFtoken( const String &token, const String &sessionId );
	void receiveMessageEstablished( FriendClaim &friendClaim, const String &relid, const String &msg );
	void receiveMessage( const String &relid, const String &msg );
	void receiveFofMessage( const String &relid, const String &msg );
	void newUser( const String &iduri, const String &privateName, const String &pass );
	void recieveMessagePrefriend( FriendClaim &claim, const String &relid, const String &msg );
	void publicKey( const String &identity );
	void relidRequest( const String &user, const String &iduri );
	void relidResponse( const String &token, const String &reqid,
			const String &identity );
	void submitBroadcast( const String &floginToken, const String &msg );
	void remoteBroadcastRequest( const String &floginToken, const String &msg );
	void remoteBroadcastResponse( const String &loginToken, const String &reqid );
	void remoteBroadcastFinal( const String &floginToken, const String &reqid );

	bool verifyBroadcast( User &user, Identity &broadcaster, FriendClaim &friendClaim, Broadcast &b );

	Allocated createRbRequestActor( long long remoteBroadcastRequestId,
		int state, int type, long long identityId );

	void submitMessage( const String &user, const String &iduri, const String &msg );

	bool haveRbSigKey( const String &rbSigKeyHash );

	void queueRbKeyFetch( User &user, FriendClaim &friendClaim, 
			Broadcast &broadcast, const String &identity,
			const String &relid, const String &rbSigKeyHash );

	bool sendBroadcastMessage();
	bool sendMessage();
	bool sendFofMessage();
	long runBroadcastQueue();
	long runMessageQueue();
	long runFofMessageQueue();
	void runQueue( const char *siteName );
	void runQueue();
	void runQueues( ConfigList &configList, int listenFd );

	void processFofMessageResult( long long getBroadcastKeyId, long long friendClaimId,
			long long actorIdentityId, const String &result );

	Allocated sendMessageNet( const String &host,
			const String &relid, const String &msg );

	Allocated sendFofMessageNet( const String &host,
			const String &relid, const String &msg );

	void sendBroadcastNet( const String &host, RecipientList &recipientList,
			const String &network, long long keyGen, const String &msg );

private:
	void checkRemoteBroadcastComplete( User &user, long long remoteBroadcastRequestId );

	void verifyRemoteBroadcast( Identity &publisherId, Identity &authorId, 
		UserMessageParser &msgParser );

	long long storeGetRelid( User &user, Identity &identity,
			long long friendClaimId, int keyPriv, const String &relid );
	long long storePutRelid( User &user, Identity &identity,
			long long friendClaimId, int keyPriv, const String &relid );

	void encryptRemoteBroadcastAuthor( User &user, Identity &publisherId,
			FriendClaim &friendClaim, const String &reqid, const String &token,
			const String &network, long long generation, const String &recipients,
			const String &plainMsg );

	void encryptRemoteBroadcastSubject( User &user, Identity &publisherId,
			FriendClaim &friendClaim, const String &reqid, const String &token,
			const String &network, long long keyGen, const String &recipients,
			const String &plainMsg );

	void repubRemoteBroadcastPublisher( User &user, Identity &peer,
			FriendClaim &friendClaim, const String &messageId,
			const String &network, long long generation, const String &recipients );

	void repubRemoteBroadcastAuthor( User &user,
			Identity &peer, FriendClaim &friendClaim,
			const String &publisherIduri, const String &messageId,
			const String &network, long long generation, const String &recipients );

	void repubRemoteBroadcastSubject( User &user,
			Identity &peer, FriendClaim &friendClaim,
			const String &publisheriduri, const String &messageId,
			const String &network, long long generation, const String &recipients );

	void returnRemoteBroadcastAuthor( User &user, Identity &identity,
			const String &reqid, const String &msg );
	void returnRemoteBroadcastSubject( User &user, Identity &identity,
			const String &reqid, const String &msg );

	void notifyAccept( User &user, Identity &identity, const String &peerNotifyReqid );
	void registered( User &user, Identity &identity, 
			const String &peerNotifyReqid, const String &friendClaimSigKey );

	void storeBroadcastKey( User &user, Identity &identity, FriendClaim &friendClaim,
			const String &distName, long long generation, const String &bkKeys );

	void receiveBroadcast( const String &relid, const String &network, 
			long long keyGen, const String &msg );

	void userMessage( MYSQL *mysql, const String &user,
			const String &friendId, const String &body );
	
	void queueBroadcast( User &user, String &msg );

	void queueMessage( User &user, const String &iduri, const String &putRelid, const String &msg );

	Allocated sendMessageNow( User &user,
			const char *toIdentity, const char *putRelid, const String &msg );

	void queueFofMessage( long long bkId, const String &relid, FriendClaim &friendClaim,
		Identity &recipient, const String &msg );

	void sendBroadcastKey( User &user, Identity &identity, 
			FriendClaim &friendClaim, long long networkId );

	void addToPrimaryNetwork( User &user, Identity &identity );

	void parseBroadcast( Broadcast &b, const String &msg );
	void broadcastContent( Broadcast &broadcast, const String &msg );
	void remoteBroadcastPublisher( Broadcast &b, const String &publisher, const String &msg );
	void remoteBroadcastAuthor( Broadcast &b, const String &author, const String &msg );
	void remoteBroadcastSubject( Broadcast &b, const String &subject, const String &msg );

	Allocated fetchPublicKeyNet( const String &host, const String &user );

	Allocated fetchRequestedRelidNet( const String &host, const String &reqid );
	Allocated fetchResponseRelidNet( const String &host, const String &reqid );
	Allocated fetchFtokenNet( const String &host, const String &reqid );

	void fetchPublicKey( Identity &identity );

	void newBroadcastKey( long long friendGroupId, long long generation );
	long long addNetwork( long long userId, const String &privateName );

	void broadcastSuccessAuthor( User &user, Identity &identity, const String &messageId );
	void broadcastSuccessSubject( User &user, Identity &identity, const String &messageId );
	void fetchRbBroadcastKey( User &user, Identity &friendId, FriendClaim &friendClaim,
			Identity &senderId, const String &distName, long long generation, const String &memberProof );

	MYSQL *mysql;
};

struct TokenFlusher
:
	public ConfigCtx
{
	TokenFlusher( Config *c, NotifAgent &notifAgent )
	:
		ConfigCtx(c),
		mysql(0),
		notifAgent(notifAgent)
	{}

	MYSQL *mysql;
	NotifAgent &notifAgent;

	void flush();
	void flushLoginTokens();
	void flushFloginTokens();
};

Allocated sha1( const String &src );
Allocated makeIduriHash( const char *identity );
long long findPrimaryNetworkId( MYSQL *mysql, User &user );
Allocated findPrimaryNetworkName( MYSQL *mysql, User &user );

#define LOGIN_TOKEN_LASTS 86400

struct Global
{
	Global()
	:
		pid(0),
		privPid(0),
		notifPid(0),
		privCmdFd(-1),
		notifCmdFd(-1),
		background(false),
		logFile(0),
		enabledRealms(0),
		tokenFlush(true),
		issueCommand(false),
		numCommandArgs(0),
		commandArgs(0)
	{}
		
	pid_t pid;
	pid_t privPid;
	pid_t notifPid;

	int privCmdFd;
	int notifCmdFd;

	uid_t dsnpdUid;
	uid_t dsnpdGid;

	uid_t privUid;
	uid_t privGid;

	uid_t notifUid;
	uid_t notifGid;

	bool background;

	FILE *logFile;
	long enabledRealms;

	bool tokenFlush;
	bool issueCommand;

	int numCommandArgs;
	char *const* commandArgs;
};

extern Global gbl;

/* Ignore a signal. */
void thatsOkay( int signum );

int listenFork( int port );
int keyAgentProcess( int fd );
int notificationProcess( int listenFd );
void serverParseLoop( ConfigList &configList, KeyAgent &keyAgent, 
		NotifAgent &notifAgent, TlsContext &tlsContext, BioWrapParse &bioWrap );

struct Reap
{
	Reap( pid_t pid )
		: pid(pid) {}

	pid_t pid;

	Reap *prev, *next;
};

typedef DList<Reap> ReapList;

enum DispatchType
{
	Command = 1,
	ServerProcess,
	QueueRun,
	StateChange
};

struct ListenFork
{
	ReapList reapList;

	int reapChildren( bool wait );
	void finalTimerRun( Config *c );
	void initialTimerRun( Config *c );
	void deliverQueueRun( Config *c, TlsContext &tlsContext, int listenFd );
	void dispatchQueueRun( Config *c, TlsContext &tlsContext, int listenFd );
	void dispatchStateChange( Config *c, TlsContext &tlsContext, int listenFd );
	void dispatch( Config *c, TlsContext &tlsContext, DispatchType dispatchType,
			int listenFd, int sockFd, sockaddr_in *peer, socklen_t peerLen );
	void dispatchIssueCommand( Config *c, TlsContext &tlsContext );
	int run( int port );
};

int extractFd( int channelFd, msghdr *msg );

long stringLength( const String &s );
long binLength( const String &bin );
long sixtyFourBitLength();
u_char *writeType( u_char *dest, u_char type );
u_char *writeString( u_char *dest, const String &s );
u_char *writeBin( u_char *dest, const String &bin );
u_char *write64Bit( u_char *dest, u_int64_t i );

Allocated consBroadcastKey( const String &distName, long long generation, const String &bkKeys );
Allocated consRegistered( const String &peerNotifyReqid, const String &friendClaimSigKey );
Allocated consNotifyAccept( const String &peerNotifyReqid );
Allocated consEncryptRemoteBroadcastAuthor( 	
		const String &authorReturnReqid, const String &floginToken, 
		const String &distName, long long generation, 
		const String &recipients, const String &plainMsg );
Allocated consEncryptRemoteBroadcastSubject(
		const String &reqid, const String &authorHash,
		const String &distName, long long generation, 
		const String &recipients, const String &plainMsg );
Allocated consRepubRemoteBroadcastPublisher(
		const String &messageId, const String &distName,
		long long generation, const String &recipients );
Allocated consRepubRemoteBroadcastAuthor(
		const String &publisher, const String &messageId,
		const String &distName, long long generation, const String &recipients );
Allocated consRepubRemoteBroadcastSubject(
		const String &publisher, const String &messageId,
		const String &distName, long long generation, 
		const String &recipients );
Allocated consReturnRemoteBroadcastAuthor(
		const String &reqid, const String &packet );
Allocated consReturnRemoteBroadcastSubject(
		const String &returnReqid, const String &packet );
Allocated consBroadcastSuccessAuthor( const String &messageId );
Allocated consBroadcastSuccessSubject( const String &messageId );
Allocated consUserMessage( const String &msg );

Allocated consSendRbBroadcastKey( const String &rbSigKeyHash );
Allocated consFetchRbBroadcastKey( const String distName, long long generation, const String &memberProof );

Allocated consRet0( );
Allocated consRet1( const String &arg );

int transmitFd( int channelFd, char cmd, int fd );
int extractFd( int channelFd, msghdr *msg );

bool checkDeliveryQueues( MYSQL *mysql );
bool checkStateChange( MYSQL *mysql );
uint64_t nextDelivery( MYSQL *mysql );

#endif
