#ifndef _DISTTREE_H
#define _DISTTREE_H

#include <stdio.h>
#include <map>
#include <string>
#include <list>

using std::map;
using std::string;
using std::pair;
using std::list;

struct FriendNode
{
	FriendNode( long long friendClaimId, string identity, long long generation )
	:
		friendClaimId(friendClaimId),
		identity(identity),
		generation(0),
		isRoot(false),
		parent(0),
		left(0),
		right(0)
	{}

	long long friendClaimId;
	string identity;
	long long generation;

	bool isRoot;
	FriendNode *parent, *left, *right;
};

typedef map<string, FriendNode*> NodeMap;
typedef list<FriendNode*> NodeList;

void load_tree( MYSQL *mysql, const char *user, long long generation, NodeList &roots );
int forwardTreeReset( MYSQL *mysql, const char *user, const char *group );
int forwardTreeInsert( MYSQL *mysql, const char *user, const char *identity, const char *relid );
int checkTree( MYSQL *mysql, const char *user, const char *group );
void putTreeAdd( MYSQL *mysql, const char *user, const char *group, long long friendGroupId,
		const char *identity, const char *relid );
void putTreeDel( MYSQL *mysql, const char *user, long long userId, 
		const char *group, long long friendGroupId,
		const char *identity, const char *relid );

#endif
