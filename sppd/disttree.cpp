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

#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <string>
#include <list>

using std::map;
using std::string;
using std::pair;
using std::list;

struct FriendNode
{
	FriendNode( string identity )
	:
		identity(identity),
		parent(0),
		left(0),
		right(0)
	{}
	string identity;

	FriendNode *parent, *left, *right;
};

typedef map<string, FriendNode*> NodeMap;
typedef list<FriendNode*> NodeList;

FriendNode *find_node( char *identity, NodeMap &nodeMap )
{
	NodeMap::iterator i = nodeMap.find( identity );
	if ( i != nodeMap.end() )
		return i->second;
	else {
		FriendNode *friendNode = new FriendNode( identity );
		nodeMap.insert( pair<string, FriendNode*>( identity, friendNode ) );
		return friendNode;
	}
}

void load_tree( const char *user, MYSQL *mysql, NodeList &roots )
{
	NodeMap nodeMap;

	exec_query( mysql,
		"SELECT friend_id, put_root, put_forward1, put_forward2 "
		"FROM friend_claim "
		"WHERE user = %e",
		user );
	
	MYSQL_RES *result = mysql_use_result( mysql );
	
	while ( true ) {
		MYSQL_ROW row = mysql_fetch_row( result );

		if ( !row )
			break;

		char *parentIdent = row[0];
		int isRoot = atoi(row[1]);
		char *leftIdent = row[2];
		char *rightIdent = row[3];

		FriendNode *parent = find_node( parentIdent, nodeMap );

		if ( isRoot )
			roots.push_back( parent );

		if ( leftIdent != 0 ) {
			FriendNode *left = find_node( leftIdent, nodeMap );
			parent->left = left;
		}

		if ( rightIdent != 0 ) {
			FriendNode *right = find_node( rightIdent, nodeMap );
			parent->right = right;
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

void forward_tree_insert( MYSQL *mysql, const char *user, const char *identity )
{
	NodeList roots;
	load_tree( user, mysql, roots );

	if ( roots.size() == 0 ) {
		/* Set this friend claim to be the root of the put tree. */
		exec_query( mysql,
			"UPDATE friend_claim "
			"SET put_root = true "
			"WHERE user = %e AND friend_id = %e",
			user, identity );
	}
	else {
		NodeList queue = roots;

		FriendNode *newNode = new FriendNode( identity );

		while ( queue.size() > 0 ) {
			FriendNode *front = queue.front();
			if ( front->left != 0 )
				queue.push_back( front->left );
			else {
				front->left = newNode;
				exec_query( mysql,
					"UPDATE friend_claim "
					"SET put_forward1 = %e "
					"WHERE user = %e AND friend_id = %e",
					identity, user, front->identity.c_str() );

				send_forward_to( user, front->identity.c_str(), 1, identity );
				break;
			}

			if ( front->right != 0 )
				queue.push_back( front->right );
			else {
				front->right = newNode;
				exec_query( mysql,
					"UPDATE friend_claim "
					"SET put_forward2 = %e "
					"WHERE user = %e AND friend_id = %e",
					identity, user, front->identity.c_str() );

				send_forward_to( user, front->identity.c_str(), 2, identity );
				break;
			}

			queue.pop_front();
		}
	}
}

void test_tree()
{
	set_config_by_name( "spp" );

	/* Open the database connection. */
	MYSQL *mysql = mysql_init(0);
	MYSQL *connect_res = mysql_real_connect( mysql, c->CFG_DB_HOST, c->CFG_DB_USER, 
			c->CFG_ADMIN_PASS, c->CFG_DB_DATABASE, 0, 0, 0 );
	if ( connect_res == 0 ) {
		printf( "ERROR failed to connect to the database\r\n");
	}

	forward_tree_insert( mysql, "pat", "http://localhost/spp/jen/" );
}

