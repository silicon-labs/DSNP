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

	/* We limit to the current generation and below and do a descending sort by
	 * generation. When we traverse, we ignore nodes that we have already read
	 * in with a higher generation.  */
	DbQuery nodes( mysql,
		"SELECT friend_claim.id, friend_claim.friend_id, put_tree.generation, "
		"	put_tree.root, put_tree.forward1, put_tree.forward2, put_tree.active "
		"FROM friend_claim "
		"JOIN put_tree ON friend_claim.id = put_tree.friend_claim_id  "
		"WHERE friend_claim.user = %e AND put_tree.generation <= %L "
		"ORDER BY put_tree.generation DESC",
		user, treeGen );

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

void execWorklist( MYSQL *mysql, const char *user, long long generation,
		const char *broadcast_key, WorkList &workList )
{
	long long active_generation = -1;
	for ( WorkList::iterator i = workList.begin(); i != workList.end(); i++ ) {
		GetTreeWork *w = *i;
		debug("%s %s %s\n", w->identity, w->left, w->right );

		DbQuery localInsert( mysql,
			"INSERT INTO put_tree "
			"( friend_claim_id, generation, root, forward1, forward2, active )"
			"VALUES ( %L, %L, %l, %e, %e, %b )",
			w->friendClaimId, w->generation,
			w->isRoot, w->left, w->right, w->active );

		if ( !w->active ) {
			/* If not active, we do do not send it any messages. We just leave
			 * it alone. This can happen if a friend has been removed from
			 * friend_claim, but it's still in the put tree and old generations
			 * have yet to be deleted. */
			message( "inactive put tree node for %s, not contacting\n", w->identity );
		}
		else {
			String parent, left, right;
			parent.set("");
			left.set("");
			right.set("");

			if ( w->parent != 0 ) {
				Identity parentId( w->parent );
				parentId.parse();
				DbQuery relid( mysql,
					"SELECT put_relid FROM friend_claim WHERE user = %e AND friend_id = %e",
					user, w->parent );

				if ( relid.rows() == 0 ) {
					error( "could not find friend claim for parent "
							"put_tree node %s %s", user, w->parent );
				}
				else {
					parent.format( 
						"forward_to 0 %lld %s %s\r\n", 
						w->generation, parentId.site, relid.fetchRow()[0] );
				}
			}

			if ( w->left != 0 ) {
				Identity leftId( w->left );
				leftId.parse();
				DbQuery relid( mysql,
					"SELECT put_relid FROM friend_claim WHERE user = %e AND friend_id = %e",
					user, w->left );

				if ( relid.rows() == 0 ) {
					error( "could not find friend claim for left "
							"put_tree node %s %s", user, w->left );
				}
				else {
					left.format( 
						"forward_to 1 %lld %s %s\r\n", 
						w->generation, leftId.site, relid.fetchRow()[0] );
				}
			}

			if ( w->right != 0 ) {
				Identity rightId( w->right );
				rightId.parse();
				DbQuery relid( mysql,
					"SELECT put_relid FROM friend_claim WHERE user = %e AND friend_id = %e",
					user, w->right );

				if ( relid.rows() == 0 ) {
					error( "could not find friend claim for right "
							"put_tree node %s %s", user, w->right );
				}
				else {
					right.format( 
						"forward_to 2 %lld %s %s\r\n", 
						w->generation, rightId.site, relid.fetchRow()[0] );
				}
			}

			String msg( "%s%s%s", parent.data, left.data, right.data );
			if ( msg.length > 0 )
				queueMessage( mysql, user, w->identity, msg.data );
		}

		active_generation = w->generation;
	}

	if ( active_generation >= 0 ) {
		DbQuery updateGen( mysql,
			"UPDATE user SET tree_gen_high = %L WHERE user = %e",
			active_generation, user );
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

int forward_tree_insert( MYSQL *mysql, const char *user,
		const char *identity, const char *relid )
{
	DbQuery claim( mysql,
		"SELECT id FROM friend_claim WHERE user = %e AND friend_id = %e",
		user, identity );

	if ( claim.rows() > 0 ) {
		MYSQL_ROW row = claim.fetchRow();
		long long friendClaimId = strtoll( row[0], 0, 10 );

		/* Need the current broadcast key. */
		CurrentPutKey put( mysql, user );

		put.treeGenHigh += 1;
		WorkList workList;
		NodeList roots;

		loadTree( mysql, user, put.treeGenHigh, roots );
		insertIntoTree( workList, roots, friendClaimId, user, identity, relid, 
				put.treeGenHigh, put.broadcastKey );
		execWorklist( mysql, user, put.treeGenHigh, put.broadcastKey, workList );
	}
	return 0;
}

int forwardTreeReset( MYSQL *mysql, const char *user )
{
	message("resetting forwared tree for user %s\n", user );

	/* Need the current broadcast key. */
	CurrentPutKey put( mysql, user );

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
int checkTree( MYSQL *mysql, const char *user )
{
	/* Need the current broadcast key. */
	CurrentPutKey put( mysql, user );

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
