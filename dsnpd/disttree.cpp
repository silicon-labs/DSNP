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

#include "dsnpd.h"
#include "disttree.h"

#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <string>
#include <list>

FriendNode *find_node( NodeMap &nodeMap, char *identity, long long generation )
{
	NodeMap::iterator i = nodeMap.find( identity );
	if ( i != nodeMap.end() )
		return i->second;
	else {
		FriendNode *friendNode = new FriendNode( identity, generation );
		nodeMap.insert( pair<string, FriendNode*>( identity, friendNode ) );
		return friendNode;
	}
}

void load_tree( MYSQL *mysql, const char *user, long long generation, NodeList &roots )
{
	NodeMap nodeMap;

	exec_query( mysql,
		"SELECT friend_id, generation, root, forward1, forward2 "
		"FROM put_tree "
		"WHERE user = %e AND generation <= %L "
		"ORDER BY generation DESC",
		user, generation );
	
	MYSQL_RES *result = mysql_use_result( mysql );
	
	while ( true ) {
		MYSQL_ROW row = mysql_fetch_row( result );

		if ( !row )
			break;

		char *ident = row[0];
		long long generation = strtoll( row[1], 0, 10 );
		int isRoot = atoi(row[2]);
		char *leftIdent = row[3];
		char *rightIdent = row[4];

		FriendNode *node = find_node( nodeMap, ident, generation );

		/* Skip if we would be downgrading the generation. */
		if ( generation < node->generation ) {
			debug("skipping old generation for %s %s\n", user, ident );
			continue;
		}
		node->generation = generation;
		debug("loading %s %s\n", user, ident );

		if ( isRoot ) {
			node->isRoot = true;
			roots.push_back( node );
		}

		if ( leftIdent != 0 ) {
			/* Use generation 0 since we don't know the generation. */
			FriendNode *left = find_node( nodeMap, leftIdent, 0 );
			node->left = left;
			left->parent = node;
		}

		if ( rightIdent != 0 ) {
			FriendNode *right = find_node( nodeMap, rightIdent, 0 );
			node->right = right;
			right->parent = node;
		}
	}

	mysql_free_result( result );
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

struct GetTreeWork
{
	GetTreeWork( const char *identity, bool isRoot, const char *parent, 
			const char *left, const char *right, long long generation, const char *bk )
	:
		identity(identity), isRoot(isRoot), 
		parent(parent), left(left), right(right),
		generation(generation), broadcast_key(bk)
	{}

	const char *identity;
	bool isRoot;
	const char *parent;
	const char *left;
	const char *right;

	long long generation;
	const char *broadcast_key;
};

typedef list<GetTreeWork*> WorkList;

void exec_worklist( MYSQL *mysql, const char *user, long long generation,
		const char *broadcast_key, WorkList &workList )
{
	long long active_generation = -1;
	for ( WorkList::iterator i = workList.begin(); i != workList.end(); i++ ) {
		GetTreeWork *w = *i;
		debug("%s %s %s\n", w->identity, w->left, w->right );

		DbQuery localInsert( mysql,
			"INSERT INTO put_tree "
			"( user, friend_id, generation, root, forward1, forward2 )"
			"VALUES ( %e, %e, %L, %l, %e, %e )",
			user, w->identity, w->generation,
			w->isRoot, w->left, w->right );

		String bk( 
			"broadcast_key %lld %s\r\n", 
			w->generation, w->broadcast_key );
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

			parent.format( 
				"forward_to 0 %lld %s %s\r\n", 
				w->generation, parentId.site, relid.fetchRow()[0] );
		}

		if ( w->left != 0 ) {
			Identity leftId( w->left );
			leftId.parse();
			DbQuery relid( mysql,
				"SELECT put_relid FROM friend_claim WHERE user = %e AND friend_id = %e",
				user, w->left );

			left.format( 
				"forward_to 1 %lld %s %s\r\n", 
				w->generation, leftId.site, relid.fetchRow()[0] );
		}

		if ( w->right != 0 ) {
			Identity rightId( w->right );
			rightId.parse();
			DbQuery relid( mysql,
				"SELECT put_relid FROM friend_claim WHERE user = %e AND friend_id = %e",
				user, w->right );

			right.format( 
				"forward_to 2 %lld %s %s\r\n", 
				w->generation, rightId.site, relid.fetchRow()[0] );
		}

		String msg( "%s%s%s%s", bk.data, parent.data, left.data, right.data );
		queue_message( mysql, user, w->identity, msg.data );

		active_generation = w->generation;
	}

	if ( active_generation >= 0 ) {
		DbQuery updateGen( mysql,
			"UPDATE user SET put_generation = %L WHERE user = %e",
			active_generation, user );
	}
}

void insert_into_tree( WorkList &workList, NodeList &roots, const char *user,
		const char *identity, const char *relid, long long generation,
		const char *broadcast_key )
{
	FriendNode *newNode = new FriendNode( identity, generation );

	if ( roots.size() == 0 ) {
		/* Set this friend claim to be the root of the put tree. */
		GetTreeWork *work = new GetTreeWork( identity, 1, 0, 0, 0,
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
					front->identity.c_str(), 
					front->isRoot ? 1 : 0,
					front->parent != 0 ? front->parent->identity.c_str() : 0,
					identity, 
					front->right != 0 ? front->right->identity.c_str() : 0,
					generation, broadcast_key );
				workList.push_back( work );

				/* Need an entry for the node being inserted into the tree. It is not a
				 * root node. */
				work = new GetTreeWork( identity, 0, front->identity.c_str(), 
						0, 0, generation, broadcast_key );
				workList.push_back( work );
				break;
			}

			if ( front->right != 0 )
				queue.push_back( front->right );
			else {
				front->right = newNode;

				GetTreeWork *work = new GetTreeWork( 
					front->identity.c_str(), 
					front->isRoot ? 1 : 0,
					front->parent != 0 ? front->parent->identity.c_str() : 0,
					front->left != 0 ? front->left->identity.c_str() : 0,
					identity,
					generation, broadcast_key );
				workList.push_back( work );

				/* Need an entry for the node being inserted into the tree. It is not a
				 * root node. */
				work = new GetTreeWork( identity, 0, front->identity.c_str(),
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
	/* Need the current broadcast key. */
	long long generation;
	String broadcast_key;
	int bkres = current_put_bk( mysql, user, generation, broadcast_key );
	if ( bkres < 0 ) {
		error("failed to get current_put_bk\n");
		return -1;
	}

	generation += 1;
	WorkList workList;
	NodeList roots;

	load_tree( mysql, user, generation, roots );

	insert_into_tree( workList, roots, user, identity, relid, generation, broadcast_key );

	exec_worklist( mysql, user, generation, broadcast_key, workList );
	return 0;
}

int forward_tree_reset( MYSQL *mysql, const char *user )
{
	/* Need the current broadcast key. */
	long long generation;
	String broadcast_key;
	int bkres = current_put_bk( mysql, user, generation, broadcast_key );
	if ( bkres < 0 ) {
		error("failed to get current_put_bk\n");
		return -1;
	}

	WorkList workList;
	NodeList roots;

	DbQuery query( mysql, "SELECT friend_id, put_relid FROM friend_claim WHERE user = %e", user );
	for ( int i = 0; i < query.rows(); i++ ) {
		generation += 1;
		MYSQL_ROW row = query.fetchRow();
		insert_into_tree( workList, roots, user, row[0], row[1], generation, broadcast_key );
	}

	exec_worklist( mysql, user, generation, broadcast_key, workList );

	return 0;
}

void swap( MYSQL *mysql, const char *user, NodeList &roots, 
		FriendNode *n1, FriendNode *n2 )
{
	/* Need the current broadcast key. */
	long long generation;
	String broadcast_key;
	int bkres = current_put_bk( mysql, user, generation, broadcast_key );
	if ( bkres < 0 ) {
		error("failed to get current_put_bk\n");
		return;
	}

	generation += 1;
	WorkList workList;

	/*
	 * Put n2 into the place of n1.
	 */

	if ( n1->parent != 0 ) {
		/* Update the parent of n1 to point to n2. */
		if ( n1->parent->left == n1 ) {
			GetTreeWork *work = new GetTreeWork( 
				n1->parent->identity.c_str(), 
				n1->parent->isRoot ? 1 : 0, 
				0,
				n2->identity.c_str(), 
				n1->parent->right != 0 ? n1->parent->right->identity.c_str() : 0,
				generation, broadcast_key );

			workList.push_back( work );
		}
		else if ( n1->parent->right == n1 ) {
			GetTreeWork *work = new GetTreeWork( 
				n1->parent->identity.c_str(), 
				n1->parent->isRoot ? 1 : 0, 
				0,
				n1->parent->left != 0 ? n1->parent->left->identity.c_str() : 0,
				n2->identity.c_str(),
				generation, broadcast_key );

			workList.push_back( work );
		}
	}

	GetTreeWork *work1 = new GetTreeWork( 
		n2->identity.c_str(), 
		n1->parent == 0 ? 1 : 0, 
		0,
		n1->left != 0 ? n1->left->identity.c_str() : 0,
		n1->right != 0 ? n1->right->identity.c_str() : 0,
		generation, broadcast_key );

	workList.push_back( work1 );

	/* 
	 * Put n1 into the place of n2.
	 */

	if ( n2->parent != 0 ) {
		if ( n2->parent->left == n2 ) {
			GetTreeWork *work = new GetTreeWork( 
				n2->parent->identity.c_str(), 
				n2->parent->isRoot ? 1 : 0, 
				0,
				n1->identity.c_str(), 
				n2->parent->right != 0 ? n2->parent->right->identity.c_str() : 0,
				generation, broadcast_key );

			workList.push_back( work );
		}
		else if ( n2->parent->right == n2 ) {
			GetTreeWork *work = new GetTreeWork( 
				n2->parent->identity.c_str(), 
				n2->parent->isRoot ? 1 : 0, 
				0,
				n2->parent->left != 0 ? n2->parent->left->identity.c_str() : 0,
				n1->identity.c_str(),
				generation, broadcast_key );

			workList.push_back( work );
		}
	}

	GetTreeWork *work2 = new GetTreeWork( 
		n1->identity.c_str(), 
		n2->parent == 0 ? 1 : 0, 
		0,
		n2->left != 0 ? n2->left->identity.c_str() : 0,
		n2->right != 0 ? n2->right->identity.c_str() : 0,
		generation, broadcast_key );

	workList.push_back( work2 );

	exec_worklist( mysql, user, generation, broadcast_key, workList );
}

int forward_tree_swap( MYSQL *mysql, const char *user,
		const char *id1, const char *id2 )
{
	NodeList roots;
	DbQuery queryGen( mysql, "SELECT put_generation FROM user WHERE user = %e", user );
	long long generation = strtoll( queryGen.fetchRow()[0], 0, 10 );
	debug("loading generation: %lld\n", generation );
	load_tree( mysql, user, generation, roots );

	FriendNode *n1, *n2;
	NodeList queue = roots;
	while ( queue.size() > 0 ) {
		FriendNode *front = queue.front();

		if ( front->identity == id1 )
			n1 = front;

		if ( front->identity == id2 )
			n2 = front;
			
		if ( front->left != 0 )
			queue.push_back( front->left );

		if ( front->right != 0 )
			queue.push_back( front->right );

		queue.pop_front();
	}

	debug( "n1: %p n2: %p p1: %p p2: %p\n", n1, n2, n1->parent, n2->parent );
	swap( mysql, user, roots, n1, n2 );

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
