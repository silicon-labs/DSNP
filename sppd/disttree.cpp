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

#include "sppd.h"
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
		"SELECT friend_id, generation, put_root, put_forward1, put_forward2 "
		"FROM put_tree "
		"WHERE user = %e AND generation <= %L "
		"ORDER BY generation DESC",
		user, generation );
	
	MYSQL_RES *result = mysql_use_result( mysql );
	
	while ( true ) {
		MYSQL_ROW row = mysql_fetch_row( result );

		if ( !row )
			break;

		char *parentIdent = row[0];
		long long generation = strtoll( row[1], 0, 10 );
		int isRoot = atoi(row[2]);
		char *leftIdent = row[3];
		char *rightIdent = row[4];

		FriendNode *parent = find_node( nodeMap, parentIdent, generation );

		/* Skip if we would be downgrading the generation. */
		if ( generation < parent->generation ) {
			printf("skipping old generation for %s %s\n", user, parentIdent );
			continue;
		}
		parent->generation = generation;
		printf("loading %s %s\n", user, parentIdent );

		if ( isRoot )
			roots.push_back( parent );

		if ( leftIdent != 0 ) {
			/* Use generation 0 since we don't know the generation. */
			FriendNode *left = find_node( nodeMap, leftIdent, 0 );
			parent->left = left;
			left->parent = parent;
		}

		if ( rightIdent != 0 ) {
			FriendNode *right = find_node( nodeMap, rightIdent, 0 );
			parent->right = right;
			right->parent = right;
		}
	}

	mysql_free_result( result );
}

void print_node( FriendNode *node, int level )
{
	if ( node != 0 ) {
		for ( int i = 0; i < level; i++ )
			printf( "    " );

		printf( "%s\n", node->identity.c_str() );

		print_node( node->left, level+1 );
		print_node( node->right, level+1 );
	}
}

int forward_tree_insert( MYSQL *mysql, const char *user,
		const char *identity, const char *relid )
{
	DbQuery genQuery( mysql,
		"SELECT put_generation from user where user = %e", user );
	if ( genQuery.rows() != 1 )
		return -1;
	long long generation = strtoll( genQuery.fetchRow()[0], 0, 10 );

	/* Insert an entry for this relationship. */
	exec_query( mysql, 
		"INSERT INTO put_tree "
		"( user, friend_id, generation, put_root )"
		"VALUES ( %e, %e, %L, 0 ) ",
		user, identity, generation );

	NodeList roots;
	load_tree( mysql, user, 1, roots );

	Identity id( identity );
	id.parse();

	if ( roots.size() == 0 ) {
		/* Set this friend claim to be the root of the put tree. */
		exec_query( mysql,
			"UPDATE put_tree "
			"SET put_root = true "
			"WHERE user = %e AND friend_id = %e",
			user, identity );
	}
	else {
		NodeList queue = roots;

		FriendNode *newNode = new FriendNode( identity, generation );

		while ( queue.size() > 0 ) {
			FriendNode *front = queue.front();
			if ( front->left != 0 )
				queue.push_back( front->left );
			else {
				front->left = newNode;

				exec_query( mysql,
					"UPDATE put_tree "
					"SET put_forward1 = %e "
					"WHERE user = %e AND friend_id = %e",
					identity, user, front->identity.c_str() );

				send_forward_to( mysql, user, front->identity.c_str(), 1,
						generation, id.site, relid );
				break;
			}

			if ( front->right != 0 )
				queue.push_back( front->right );
			else {
				front->right = newNode;

				exec_query( mysql,
					"UPDATE put_tree "
					"SET put_forward2 = %e "
					"WHERE user = %e AND friend_id = %e",
					identity, user, front->identity.c_str() );

				send_forward_to( mysql, user, front->identity.c_str(), 2,
						generation, id.site, relid );
				break;
			}

			queue.pop_front();
		}
	}
	return 0;
}

struct GetTreeWork
{
	GetTreeWork( const char *identity, const char *left, const char *right )
		: identity(identity), left(left), right(right) {}

	const char *identity;
	const char *left;
	const char *right;
};

typedef list<GetTreeWork*> WorkList;


void swap( MYSQL *mysql, const char *user, NodeList &roots, FriendNode *n1, FriendNode *n2 )
{
	WorkList workList;

	/*
	 * Put n2 into the place of n1.
	 */

	if ( n1->parent != 0 ) {
		/* Update the parent of n1 to point to n2. */
		if ( n1->parent->left == n1 ) {
			DbQuery updateLeft( mysql,
				"UPDATE put_tree SET put_forward1 = %e "
				"WHERE user = %e AND friend_id = %e",
				n2->identity.c_str(), user, n1->parent->identity.c_str() );

			GetTreeWork *work = new GetTreeWork( 
				n1->parent->identity.c_str(), 
				n2->identity.c_str(), 
				n1->parent->right != 0 ? n1->parent->right->identity.c_str() : 0 );

			workList.push_back( work );
		}
		else if ( n1->parent->right == n1 ) {
			DbQuery updateLeft( mysql,
				"UPDATE put_tree SET put_forward2 = %e "
				"WHERE user = %e AND friend_id = %e",
				n2->identity.c_str(), user, n1->parent->identity.c_str() );

			GetTreeWork *work = new GetTreeWork( 
				n1->parent->identity.c_str(), 
				n1->parent->left != 0 ? n1->parent->left->identity.c_str() : 0,
				n2->identity.c_str() );

			workList.push_back( work );
		}
	}

	DbQuery updateLeft( mysql,
		"UPDATE put_tree SET put_root = %l, put_forward1 = %e, put_forward2 = %e "
		"WHERE user = %e AND friend_id = %e",
		n1->parent == 0 ? 1 : 0, 
		n1->left != 0 ? n1->left->identity.c_str() : 0 , 
		n1->right != 0 ? n1->right->identity.c_str() : 0, 
		user, n2->identity.c_str() );
		
	GetTreeWork *work1 = new GetTreeWork( 
		n2->identity.c_str(), 
		n1->left != 0 ? n1->left->identity.c_str() : 0,
		n1->right != 0 ? n1->right->identity.c_str() : 0 );

	workList.push_back( work1 );

	/* 
	 * Put n1 into the place of n2.
	 */

	if ( n2->parent != 0 ) {
		if ( n2->parent->left == n2 ) {
			DbQuery updateRight( mysql,
				"UPDATE put_tree SET put_forward1 = %e "
				"WHERE user = %e AND friend_id = %e",
				n1->identity.c_str(), user, n2->parent->identity.c_str() );

			GetTreeWork *work = new GetTreeWork( 
				n2->parent->identity.c_str(), 
				n1->identity.c_str(), 
				n2->parent->right != 0 ? n2->parent->right->identity.c_str() : 0 );

			workList.push_back( work );
		}
		else if ( n2->parent->right == n2 ) {
			DbQuery updateRight( mysql,
				"UPDATE put_tree SET put_forward2 = %e "
				"WHERE user = %e AND friend_id = %e",
				n1->identity.c_str(), user, n2->parent->identity.c_str() );

			GetTreeWork *work = new GetTreeWork( 
				n2->parent->identity.c_str(), 
				n2->parent->left != 0 ? n2->parent->left->identity.c_str() : 0,
				n1->identity.c_str() );

			workList.push_back( work );
		}
	}

	DbQuery updateRight( mysql,
		"UPDATE put_tree SET put_root = %l, put_forward1 = %e, put_forward2 = %e "
		"WHERE user = %e AND friend_id = %e",
		n2->parent == 0 ? 1 : 0,
		n2->left != 0 ? n2->left->identity.c_str() : 0, 
		n2->right != 0 ? n2->right->identity.c_str() : 0, 
		user, n1->identity.c_str() );

	GetTreeWork *work2 = new GetTreeWork( 
		n1->identity.c_str(), 
		n2->left != 0 ? n2->left->identity.c_str() : 0,
		n2->right != 0 ? n2->right->identity.c_str() : 0 );

	workList.push_back( work2 );

	/* Need the current broadcast key. */
	long long generation;
	String broadcast_key;
	current_put_bk( mysql, user, generation, broadcast_key );
	generation += 1;

	for ( WorkList::iterator i = workList.begin(); i != workList.end(); i++ ) {
		GetTreeWork *w = *i;
		printf("%s %s %s\n", w->identity, w->left, w->right );
		send_broadcast_key( mysql, user, w->identity, generation, broadcast_key );

		if ( w->left != 0 ) {
			Identity leftId( w->left );
			leftId.parse();
			DbQuery relid( mysql,
				"SELECT put_relid FROM friend_claim WHERE user = %e AND friend_id = %e",
				user, w->identity );
			send_forward_to( mysql, user, w->identity, 1, generation,
					leftId.site, relid.fetchRow()[0] );
		}

		if ( w->right != 0 ) {
			Identity rightId( w->right );
			rightId.parse();
			DbQuery relid( mysql,
				"SELECT put_relid FROM friend_claim WHERE user = %e AND friend_id = %e",
				user, w->identity );
			send_forward_to( mysql, user, w->identity, 2, generation,
					rightId.site, relid.fetchRow()[0] );
		}
	}
}

int forward_tree_swap( MYSQL *mysql, const char *user,
		const char *id1, const char *id2 )
{
	NodeList roots;
	load_tree( mysql, user, 1, roots );

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

	printf( "n1: %p n2: %p p1: %p p2: %p\n", n1, n2, n1->parent, n2->parent );
	swap( mysql, user, roots, n1, n2 );

	return 0;
}
