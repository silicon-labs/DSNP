<?php

define( 'DS', DIRECTORY_SEPARATOR );
define( 'ROOT', dirname(__FILE__) );
define( 'PREFIX', dirname(dirname(dirname(ROOT))) );

/* Must be run as root. */
if ( posix_getuid() != 0 ) {
	fprintf( STDERR, "error: command.php must be run as root\n" );
	exit(1);
}

function userError( $code, $args )
{
	fwrite( STDERR, "user error: $code\n" );
	#print_r( $args );
}

require( ROOT . "/schema.php" );
require( ROOT . "/errdef.php" );
require( ROOT . "/definitions.php" );
require( ROOT . "/message.php" );
require( ROOT . "/regexes.php" );
require( ROOT . "/connection.php" );

# Move to the php directory. */
$dir = str_replace( 'command.php', '', array_shift( $argv ) );
chdir( $dir );

$CFG = NULL;
$cmdv = $argv;

# The DSNPd bin.
$DSNPd = "$WITH_DSNPD/bin/dsnpd";

# Set the global that will give us the right site. FIXME: this the right name
# to use here. Might be causing confusion with existing globals.
$_SERVER['HTTP_HOST'] = '';
$_SERVER['REQUEST_URI'] = '';
$CFG_NAME = array_shift( $cmdv );
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

function commandNewUser( $user, $pass )
{
	global $CFG;
	global $DSNPd;
	global $WWW_USER;

	/* Default user */
	$cfgName = $CFG['NAME'];
	$idurl = "{$CFG['URI']}{$user}/";
	$iduri = idurlToIduri( $idurl );
	$hash = iduriHash( $iduri );
	$privateName = "default-network";

	/*
	 * Create the user in DSNPd.
	 */
	$backendNewUser = 
			"$DSNPd -m $cfgName new-user $iduri $privateName $pass";
	print( "executing: $backendNewUser\n" );
	system( $backendNewUser, $result );
	if ( $result != 0 ) {
		die( "failed to register user with DSNPd\n" );
	}

	/*
	 * User table.
	 */
	dbQuery( "INSERT IGNORE INTO user ( user ) VALUES ( %e )", $user );
	$userId = lastInsertId();


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
			"( user_id, type, private_name, key_gen ) " .
			"VALUES ( %L, %l, %e, 1 )",
			$userId, NET_TYPE_PRIMARY, $privateName );

	$networkId = lastInsertId();

	$dataDir = PREFIX . "/var/lib/choicesocial/{$CFG['NAME']}/data";

	/* Create the photo directory. */
	$userDataDir = "$dataDir/$user";
	$createPhotoDir = 
			"rm -Rf $userDataDir; " .
			"mkdir $userDataDir; " .
			"chmod 700 $userDataDir; " .
			"chown $WWW_USER:$WWW_USER $userDataDir; ";
	system( $createPhotoDir );

	dbQuery(
			"UPDATE user " .
			"SET identity_id = %L, relationship_id = %L, network_id = %L ".
			"WHERE id = %L ",
			$identityId, $relationshipId, $networkId, $userId );
	
}

switch ( strtolower( $notification_type ) ) {
	case "new-user": {
		$user = $cmdv[0];
		$pass = $cmdv[1];

		fwrite( STDERR, "command.php: new_user $user $pass\n" );
		commandNewUser( $user, $pass );
		break;
	}
}

?>
