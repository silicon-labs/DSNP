/*
 *  Copyright (c) 2009, Adrian Thurston <thurston@complang.org>
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "dsnp.h"
#include "disttree.h"

#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <string>
#include <list>

struct GetTreeWork
{
	GetTreeWork( long long friendClaimId, const char *identity, bool isRoot, 
			const char *parent, const char *left, const char *right,
			long long generation, const char *bk )
	:
		friendClaimId(friendClaimId),
		identity(identity), isRoot(isRoot), 
		parent(parent), left(left), right(right),
		generation(generation), broadcast_key(bk),
		active(true)
	{}

	long long friendClaimId;
	const char *identity;
	bool isRoot;
	const char *parent;
	const char *left;
	const char *right;

	long long generation;
	const char *broadcast_key;
	bool active;
};

typedef list<GetTreeWork*> WorkList;
typedef map<string, long long> IdMap;

FriendNode *findNode( NodeMap &nodeMap, long long friendClaimId, char *identity, long long generation )
{
	NodeMap::iterator i = nodeMap.find( identity );
	if ( i != nodeMap.end() )
		return i->second;
	else {
		FriendNode *friendNode = new FriendNode( friendClaimId, identity, generation );
		nodeMap.insert( pair<string, FriendNode*>( identity, friendNode ) );
		return friendNode;
	}
}

void loadTree( MYSQL *mysql, const char *user, long long treeGen, NodeList &roots )
{
	message("loading tree for user %s generation %lld\n", user, treeGen );

	NodeMap nodeMap;

	DbQuery group( mysql,
		"SELECT friend_group.id "
		"FROM user "
		"JOIN friend_group ON user.id = friend_group.id "
		"WHERE user.user = %e AND friend_group.name = %e "
	);
	
	if ( group.rows() == 0 )
		return;
	
	long long friendGroupId = strtoll( group.fetchRow()[0], 0, 10 );

	/* We limit to the current generation and below and do a descending sort by
	 * generation. When we traverse, we ignore nodes that we have already read
	 * in with a higher generation.  */
	DbQuery nodes( mysql,
		"SELECT friend_claim.id, friend_claim.friend_id, put_tree.generation, "
		"	put_tree.root, put_tree.forward1, put_tree.forward2, put_tree.active "
		"FROM friend_claim "
		"JOIN put_tree ON friend_claim.id = put_tree.friend_claim_id  "
		"WHERE friend_claim.user = %e AND put_tree.friend_group_id = %L AND "
		"	put_tree.state = 2 AND put_tree.generation <= %L "
		"ORDER BY put_tree.generation DESC",
		user, friendGroupId, treeGen );

	/* One pass to load the nodes. */
	while ( true ) {
		MYSQL_ROW row = nodes.fetchRow();
		if ( !row )
			break;

		long long friendClaimId = strtoll( row[0], 0, 10 );
		char *ident = row[1];
		long long nodeGen = strtoll( row[2], 0, 10 );
		int isRoot = atoi(row[3]);
		int active = atoi(row[6]);

		FriendNode *node = findNode( nodeMap, friendClaimId, ident, nodeGen );

		/* Skip if we would be downgrading the generation. */
		if ( nodeGen < node->generation ) {
			message("skipping old generation for %s %s\n", user, ident );
			continue;
		}
		node->generation = nodeGen;
		message("loading %s %s%s\n", user, ident, !active ? " (not active)" : "" );

		if ( isRoot ) {
			node->isRoot = true;
			roots.push_back( node );
		}
	}

	/* Another pass to set the left and right pointers so we can rely on them
	 * being present. */
	nodes.seek( 0 );
	while ( true ) {
		MYSQL_ROW row = nodes.fetchRow();
		if ( !row )
			break;

		char *ident = row[1];
		char *leftIdent = row[4];
		char *rightIdent = row[5];

		FriendNode *node = nodeMap[ident];

		if ( leftIdent != 0 ) {
			/* Use generation 0 since we don't know the generation. */
			FriendNode *left = nodeMap[leftIdent];
			if ( left == 0 ) {
				error("put tree node ( %s, %s, %lld ) has dangling left pointer\n", 
						user, node->identity.c_str(), node->generation );
			}
			else {
				node->left = left;
				left->parent = node;
			}
		}

		if ( rightIdent != 0 ) {
			FriendNode *right = nodeMap[rightIdent];
			if ( right == 0 ) {
				error("put tree node ( %s, %s, %lld ) has dangling right pointer\n", 
						user, node->identity.c_str(), node->generation );
			}
			else {
				node->right = right;
				right->parent = node;
			}
		}
	}
}

void print_node( FriendNode *node, int level )
{
	if ( node != 0 ) {
		for ( int i = 0; i < level; i++ )
			debug( "    " );

		debug( "%s\n", node->identity.c_str() );

		print_node( node->left, level+1 );
		print_node( node->right, level+1 );
	}
}

void insertIntoTree( WorkList &workList, NodeList &roots, long long friendClaimId, 
		const char *user, const char *identity, const char *relid, long long generation,
		const char *broadcast_key )
{
	FriendNode *newNode = new FriendNode( friendClaimId, identity, generation );

	if ( roots.size() == 0 ) {
		/* Set this friend claim to be the root of the put tree. */
		GetTreeWork *work = new GetTreeWork( friendClaimId, identity, 1, 0, 0, 0,
				generation, broadcast_key );
		workList.push_back( work );
		roots.push_back( newNode );
		newNode->isRoot = true;
	}
	else {
		NodeList queue = roots;

		while ( queue.size() > 0 ) {
			FriendNode *front = queue.front();
			if ( front->left != 0 )
				queue.push_back( front->left );
			else {
				front->left = newNode;

				GetTreeWork *work = new GetTreeWork( 
					front->friendClaimId,
					front->identity.c_str(), 
					front->isRoot ? 1 : 0,
					front->parent != 0 ? front->parent->identity.c_str() : 0,
					identity, 
					front->right != 0 ? front->right->identity.c_str() : 0,
					generation, broadcast_key );
				workList.push_back( work );

				/* Need an entry for the node being inserted into the tree. It is not a
				 * root node. */
				work = new GetTreeWork( friendClaimId, identity, 0, front->identity.c_str(), 
						0, 0, generation, broadcast_key );
				workList.push_back( work );
				break;
			}

			if ( front->right != 0 )
				queue.push_back( front->right );
			else {
				front->right = newNode;

				GetTreeWork *work = new GetTreeWork( 
					front->friendClaimId,
					front->identity.c_str(), 
					front->isRoot ? 1 : 0,
					front->parent != 0 ? front->parent->identity.c_str() : 0,
					front->left != 0 ? front->left->identity.c_str() : 0,
					identity,
					generation, broadcast_key );
				workList.push_back( work );

				/* Need an entry for the node being inserted into the tree. It is not a
				 * root node. */
				work = new GetTreeWork( friendClaimId, identity, 0, front->identity.c_str(),
						0, 0, generation, broadcast_key );
				workList.push_back( work );
				break;
			}

			queue.pop_front();
		}
	}
}

void putTreeAdd( MYSQL *mysql, const char *user, const char *network,
		long long networkId, const char *identity, const char *relid )
{
	DbQuery claim( mysql,
		"SELECT id FROM friend_claim WHERE user = %e AND friend_id = %e",
		user, identity );

	if ( claim.rows() > 0 ) {
		MYSQL_ROW row = claim.fetchRow();
		long long friendClaimId = strtoll( row[0], 0, 10 );

		/* Need the current tree generation. */
		CurrentPutKey put( mysql, user, network );

		DbQuery( mysql,
			"INSERT INTO put_tree "
			"( friend_claim_id, network_id, generation, root, active, state ) "
			"VALUES ( %L, %L, %L, false, true, 1 )",
			friendClaimId, networkId, put.treeGenHigh );
	}
}

void putTreeDel( MYSQL *mysql, const char *user, long long userId, 
		const char *network, long long networkId,
		const char *identity, const char *relid )
{
	DbQuery claim( mysql,
		"SELECT id FROM friend_claim WHERE user = %e AND friend_id = %e",
		user, identity );

	if ( claim.rows() > 0 ) {
		MYSQL_ROW row = claim.fetchRow();
		long long friendClaimId = strtoll( row[0], 0, 10 );

		message("resetting forwared tree for user %s, excluding %s\n", user, identity );

		/* Need the current broadcast key. */
		CurrentPutKey put( mysql, user, network );
		long long newTreeGen = put.treeGenHigh + 1;

		DbQuery load( mysql,
			"INSERT INTO put_tree "
			"( friend_claim_id, network_id, generation, root, active, state ) "
			"SELECT friend_claim.id, %L, %L, false, true, 1 "
			"FROM friend_claim "
			"JOIN network_member ON friend_claim.id = network_member.friend_claim_id "
			"WHERE user = %e AND network_member.network_id = %L AND friend_claim.id != %L ",
			networkId, newTreeGen, user, networkId, friendClaimId );

		DbQuery( mysql,
			"UPDATE network "
			"SET tree_gen_low = %L, tree_gen_high = %L "
			"WHERE id = %L",
			newTreeGen, newTreeGen, networkId );
	}
}

int forwardTreeReset( MYSQL *mysql, const char *user, const char *group )
{
	message("resetting forwared tree for user %s\n", user );

	/* Need the current broadcast key. */
	CurrentPutKey put( mysql, user, group );
	long long newTreeGen = put.treeGenHigh + 1;

	DbQuery load( mysql,
		"INSERT INTO put_tree "
		"( friend_claim_id, generation, root, active, state ) "
		"SELECT id, %L, false, true, 1 FROM friend_claim WHERE user = %e ",
		newTreeGen, user );

	DbQuery( mysql,
		"UPDATE user SET tree_gen_low = %L, tree_gen_high = %L WHERE user = %e ",
		newTreeGen, newTreeGen, user );

	return 0;
}

/* This should perform some sanity checks on the distribution tree. */
int checkTree( MYSQL *mysql, const char *user, const char *group )
{
	/* Need the current broadcast key. */
	CurrentPutKey put( mysql, user, group );

	WorkList workList;
	NodeList roots;

	loadTree( mysql, user, put.treeGenHigh+1, roots );
	return 0;
}



/* 

Bottom up tree building, try to find:

Try to find two trees of same height, use the shortest such pair. Make the new
node a parent of these nodes.

If no pair of the same height is found then make a single.

Example:

x

x x

 x
x x

 x
x x  x

 x
x x   x x

 x     x
x x   x x

    x
 x     x
x x   x x

    x
 x     x
x x   x x   x

    x
 x     x
x x   x x   x x

    x
 x     x     x
x x   x x   x x

    x
 x     x     x
x x   x x   x x   x


    x
 x     x     x
x x   x x   x x   x x

    x
 x     x     x     x
x x   x x   x x   x x

    x           x
 x     x     x     x
x x   x x   x x   x x

          x
    x           x
 x     x     x     x
x x   x x   x x   x x

          x
    x           x
 x     x     x     x
x x   x x   x x   x x   x x

          x
    x           x
 x     x     x     x     x
x x   x x   x x   x x   x x

          x
    x           x
 x     x     x     x     x
x x   x x   x x   x x   x x   x

          x
    x           x
 x     x     x     x     x
x x   x x   x x   x x   x x   x x

          x
    x           x
 x     x     x     x     x     x
x x   x x   x x   x x   x x   x x

          x
    x           x           x
 x     x     x     x     x     x
x x   x x   x x   x x   x x   x x

          x
    x           x           x
 x     x     x     x     x     x
x x   x x   x x   x x   x x   x x   x

          x
    x           x           x
 x     x     x     x     x     x
x x   x x   x x   x x   x x   x x   x x

          x
    x           x           x
 x     x     x     x     x     x     x
x x   x x   x x   x x   x x   x x   x x

          x
    x           x           x
 x     x     x     x     x     x     x
x x   x x   x x   x x   x x   x x   x x   x

          x
    x           x           x
 x     x     x     x     x     x     x
x x   x x   x x   x x   x x   x x   x x   x x

          x
    x           x           x
 x     x     x     x     x     x     x     x
x x   x x   x x   x x   x x   x x   x x   x x

          x
    x           x           x           x
 x     x     x     x     x     x     x     x
x x   x x   x x   x x   x x   x x   x x   x x

          x                       x
    x           x           x           x
 x     x     x     x     x     x     x     x
x x   x x   x x   x x   x x   x x   x x   x x

                      x
          x                       x
    x           x           x           x
 x     x     x     x     x     x     x     x
x x   x x   x x   x x   x x   x x   x x   x x

*/
