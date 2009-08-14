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
	FriendNode( string identity, long long generation )
	:
		identity(identity),
		generation(0),
		isRoot(false),
		parent(0),
		left(0),
		right(0)
	{}
	string identity;
	long long generation;

	bool isRoot;
	FriendNode *parent, *left, *right;
};

typedef map<string, FriendNode*> NodeMap;
typedef list<FriendNode*> NodeList;

void load_tree( MYSQL *mysql, const char *user, long long generation, NodeList &roots );

#endif
