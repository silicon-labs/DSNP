<?php

define( 'DS', DIRECTORY_SEPARATOR );
define( 'ROOT', dirname(__FILE__) );
define( 'PREFIX', dirname(dirname(dirname(ROOT))) );

function userError( $code, $args )
{
	fwrite( STDERR, "user error: $code\n" );
	fwrite( STDERR, "args: " . print_r( $args, true ) );
}

require( ROOT . "/schema.php" );
require( ROOT . "/errdef.php" );
require( ROOT . "/definitions.php" );
require( ROOT . "/message.php" );
require( ROOT . "/regexes.php" );
require( ROOT . "/connection.php" );

#fwrite( STDERR, "NOTIFICATION ARRIVED:\n" );
#print_r( $argv );

# Move to the php directory. */
$dir = str_replace( 'notification.php', '', array_shift( $argv ) );
chdir( $dir );

$CFG = NULL;

$command = fgets( STDIN );
$cmdv = preg_split( '/[ \t\n\v\f\r]+/', $command );

# Set the global that will give us the right site. FIXME: this the right name
# to use here. Might be causing confusion with existing globals.
$_SERVER['HTTP_HOST'] = '';
$_SERVER['REQUEST_URI'] = '';
$CFG_COMM_KEY = array_shift( $cmdv );
require( PREFIX . '/etc/choicesocial.php' );
require( ROOT . '/selectconf.php' );

require( ROOT . '/database.php' );

$DATA_DIR = PREFIX . "/var/lib/choicesocial/{$CFG['NAME']}/data";

$notification_type = array_shift( $cmdv );

function argUser( $user )
{
	if ( ! preg_match( REGEX_USER, $user ) )
		die( "user '$user' does not validate" );
	return $user;
}

function argId( $id )
{
	if ( ! preg_match( REGEX_ID, $id ) )
		die( "id '$id' does not validate" );
	return $id;
}

function argNum( $num )
{
	if ( ! preg_match( '/^[0-9]+$/', $num ) )
		die( "number '$num' does not validate" );
	return $num;
}

function argLength( $length )
{
	if ( ! preg_match( '/^[0-9]+$/', $length ) )
		die( "length '$length' does not validate" );
	return $length;
}

function notificationLogout( $sessionId )
{
	session_id( $sessionId );
	session_start();
	session_destroy();
}

function notificationNewUser( $user, $hash, $network )
{
	global $CFG;

	# Comes in as a full IDURI, find the last component, which becomes the
	# user.
	$user = preg_replace( '/\/$/', '', $user );
	$user = preg_replace( '/^.*\//', '', $user );

	dbQuery( "INSERT IGNORE INTO user ( user ) VALUES ( %e )", $user );
	$userId = lastInsertId();

	$idurl = "{$CFG['URI']}{$user}/";
	$iduri = idurlToIduri( $idurl );

	/*
	 * Identity
	 */
	dbQuery(
			"INSERT IGNORE INTO identity ( iduri, hash ) " .
			"VALUES ( %e, %e ) ",
			$iduri, $hash );

	$identityResult = dbQuery( 
			"SELECT id FROM identity WHERE iduri = %e",
			$iduri );
	$identityId = $identityResult[0]['id'];

	/*
	 * Self-Relationship
	 */
	dbQuery(
			"INSERT INTO relationship ( user_id, type, identity_id, name ) " .
			"VALUES ( %L, %l, %L, %e ) ",
			$userId, REL_TYPE_SELF, $identityId, $user );

	$relationshipId = lastInsertId();

	/*
	 * Network
	 */

	/* Always, try to insert. Ignore failures. FIXME: need to loop on the
	 * random selection here. */
	dbQuery(
			"INSERT IGNORE INTO network " .
			"( user_id, type, dist_name, key_gen ) " .
			"VALUES ( %L, %l, %e, 1 )",
			$userId, NET_TYPE_PRIMARY, $network );

	$networkId = lastInsertId();

	$dataDir = PREFIX . "/var/lib/choicesocial/{$CFG['NAME']}/data";

	/* Create the photo directory. */
	$cmd = "umask 0077; mkdir $dataDir/$user";
	system( $cmd );

	dbQuery(
			"UPDATE user " .
			"SET identity_id = %L, relationship_id = %L, network_id = %L ".
			"WHERE id = %L ",
			$identityId, $relationshipId, $networkId, $userId );
}

function friendRequestReceived( $user, $iduri, $hash, $acceptReqid )
{
	# Pull the username from the iduri. 
	$user = preg_replace( '/\/$/', '', $user );
	$user = preg_replace( '/^.*\//', '', $user );

	$userId = findUserId( $user );

	dbQuery(
		"INSERT IGNORE INTO identity ( iduri, hash ) VALUES ( %e, %e )",
		$iduri, $hash );

	$identityId = findIdentityId( $iduri );
	$name = nameFromIduri( $iduri );

	dbQuery(
		"INSERT IGNORE INTO relationship ( user_id, type, identity_id, name ) " .
		"VALUES ( %L, %l, %L, %e )",
		$userId, REL_TYPE_FRIEND, $identityId, $name );
	
	$relationshipId = findRelationshipId( $userId, $identityId );
	dbQuery(
		"INSERT INTO friend_request " .
		"( user_id, identity_id, relationship_id, accept_reqid ) " .
		"VALUES ( %L, %L, %L, %e ) ",
		$userId, $identityId, $relationshipId, $acceptReqid );
}

function friendRequestAccepted( $user, $iduri, $acceptReqid )
{
	$user = preg_replace( '/\/$/', '', $user );
	$user = preg_replace( '/^.*\//', '', $user );

	$userId = findUserId( $user );
	$identityId = findIdentityId( $iduri );
	$relationshipId = findRelationshipId( $userId, $identityId );

	dbQuery( 
		"DELETE FROM friend_request " .
		"WHERE user_id = %L AND identity_id = %L AND accept_reqid = %e ",
		$userId, $identityId, $acceptReqid );
	
	dbQuery(
		"INSERT INTO friend_claim " .
		"( user_id, identity_id, relationship_id ) " .
		"VALUES ( %L, %L, %L );",
		$userId, $identityId, $relationshipId );
}

function friendRequestSent( $user, $iduri, $hash, $userNotifyReqid )
{
	$user = preg_replace( '/\/$/', '', $user );
	$user = preg_replace( '/^.*\//', '', $user );

	$userId = findUserId( $user );

	dbQuery(
		"INSERT IGNORE INTO identity ( iduri, hash ) VALUES ( %e, %e )",
		$iduri, $hash );

	$identityId = findIdentityId( $iduri );
	$name = nameFromIduri( $iduri );

	dbQuery(
		"INSERT IGNORE INTO relationship ( user_id, type, identity_id, name ) " .
		"VALUES ( %L, %l, %L, %e )",
		$userId, REL_TYPE_FRIEND, $identityId, $name );
	
	$relationshipId = findRelationshipId( $userId, $identityId );
	
	/* Record the sent request. */
	dbQuery( 
		"INSERT INTO sent_friend_request " .
		"( user_id, identity_id, relationship_id, user_notify_reqid ) " .
		"VALUES ( %L, %L, %L, %e );",
		$userId, $identityId, $relationshipId, $userNotifyReqid );
}


function sentFriendRequestAccepted( $user, $iduri, $userNotifyReqid )
{
	$user = preg_replace( '/\/$/', '', $user );
	$user = preg_replace( '/^.*\//', '', $user );

	$userId = findUserId( $user );
	$identityId = findIdentityId( $iduri );
	$relationshipId = findRelationshipId( $userId, $identityId );
	
	dbQuery( 
		"DELETE FROM sent_friend_request " .
		"WHERE user_id = %L AND identity_id = %L AND user_notify_reqid = %e",
		$userId, $identityId, $userNotifyReqid );

	dbQuery(
		"INSERT INTO friend_claim " .
		"( user_id, identity_id, relationship_id ) " .
		"VALUES ( %L, %L, %L );",
		$userId, $identityId, $relationshipId );
}


switch ( strtolower( $notification_type ) ) {
	case "broadcast": {
		$user = argUser( $cmdv[0] );
		$broadcaster = argId( $cmdv[1] );
		$length = argLength( $cmdv[2] );

		fwrite( STDERR, "notification.php: broadcast $user $broadcaster $length\n" );

		$user = preg_replace( '/\/$/', '', $user );
		$user = preg_replace( '/^.*\//', '', $user );

		$m = new Message;
		$m->parseBroadcast( $user, $broadcaster, $length, STDIN );
		break;
	}

	case "message": {
		$user = argUser( $cmdv[0] );
		# What do we call this?
		$sender = argId( $cmdv[1] );
		$length = argLength( $cmdv[2] );

		fwrite( STDERR, "notification.php: message $user $sender $length\n" );

		$user = preg_replace( '/\/$/', '', $user );
		$user = preg_replace( '/^.*\//', '', $user );

		$m = new Message;
		$m->parseMessage( $user, $sender, $length, STDIN );
		break;
	}

	case "logout": {
		$sessionId = $cmdv[0];
		# Don't print anything here, the session functions will issue warnings.
		# print "logout $sessionId\n";
		notificationLogout( $sessionId );
		break;
	}

	case "new_user": {
		$user = $cmdv[0];
		$hash = $cmdv[1];
		$network = $cmdv[2];

		fwrite( STDERR, "notification.php: new_user $user $hash $network\n" );
		notificationNewUser( $user, $hash, $network );
		break;
	}

	case "friend_request_received": {
		$user = $cmdv[0];
		$iduri = $cmdv[1];
		$hash = $cmdv[2];
		$acceptReqid = $cmdv[3];
		fwrite( STDERR, "notification.php: friend_request_received $user $iduri $hash $acceptReqid\n" );
		friendRequestReceived( $user, $iduri, $hash, $acceptReqid );
		break;
	}
	case "friend_request_sent": {
		$user = $cmdv[0];
		$iduri = $cmdv[1];
		$hash = $cmdv[2];
		$userNotifyReqid = $cmdv[3];
		fwrite( STDERR, "notification.php: friend_request_sent $user $iduri $hash $userNotifyReqid\n" );
		friendRequestSent( $user, $iduri, $hash, $userNotifyReqid );
		break;
	}
	case "friend_request_accepted": {
		$user = $cmdv[0];
		$iduri = $cmdv[1];
		$acceptReqid = $cmdv[2];
		fwrite( STDERR, "notification.php: friend_request_accepted $user $iduri $acceptReqid\n" );
		friendRequestAccepted( $user, $iduri, $acceptReqid );
		break;
	}
	case "sent_friend_request_accepted": {
		$user = $cmdv[0];
		$iduri = $cmdv[1];
		$userNotifyReqid = $cmdv[2];
		fwrite( STDERR, "notification.php: sent_friend_request_accepted $user $iduri $userNotifyReqid\n" );
		sentFriendRequestAccepted( $user, $iduri, $userNotifyReqid );
		break;
	}
}

print "OK\n";

?>
