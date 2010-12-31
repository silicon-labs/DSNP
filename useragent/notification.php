<?php

define( 'DS', DIRECTORY_SEPARATOR );
define( 'ROOT', dirname(__FILE__) );
define( 'PREFIX', dirname(dirname(dirname(ROOT))) );

function userError( $code, $args )
{
	print "user error: $code\n";
	print_r( $args );
}

require( ROOT . "/definitions.php" );
require( ROOT . "/message.php" );
require( ROOT . "/regexes.php" );

printf( "NOTIFICATION ARRIVED:\n" );
print_r( $argv );

# Move to the php directory. */
$dir = str_replace( 'notification.php', '', array_shift( $argv ) );
chdir( $dir );

$CFG = NULL;

# Simlate the server environment so that the right installation can be selected.
$_SERVER['HTTP_HOST'] = array_shift( $argv );
$_SERVER['REQUEST_URI'] = array_shift( $argv ) . '/';

require( PREFIX . '/etc/dsnpua.php' );
require( PREFIX . '/share/dsnp/web/database.php' );

$DATA_DIR = PREFIX . "/var/lib/dsnp/{$CFG['NAME']}/data";

$notification_type = array_shift( $argv );

# Connect to the database.
$conn = mysql_connect($CFG['DB_HOST'], $CFG['DB_USER'], $CFG['DB_PASS']) or die 
	('Could not connect to database');
mysql_select_db($CFG['DB_DATABASE']) or die
	('Could not select database ' . $CFG['DB_DATABASE']);

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

function argDate( $date )
{
	if ( ! preg_match( REGEX_DATE, $date ) )
		die( "date '$date' does not validate" );
	return $date;
}

function argTime( $time )
{
	if ( ! preg_match( REGEX_TIME, $time ) )
		die( "time '$time' does not validate" );
	return $time;
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

switch ( $notification_type ) {
	case "notification_broadcast": {
		# Read the message from stdin.
		$user = argUser( $argv[0] );
		$author = argId( $argv[1] );
		$seqNum = argNum( $argv[2] );
		$date = argDate( $argv[3] );
		$time = argTime( $argv[4] );
		$length = argLength( $argv[5] );

		$m = new Message;
		$m->parseBroadcast( $user, $author, $seqNum, $date,
				$time, $length, STDIN );
		break;
	}

	case "notification_message": {
		$user = argUser( $argv[0] );
		$author = argId( $argv[1] );
		$date = argDate( $argv[2] );
		$time = argTime( $argv[3] );
		$length = argLength( $argv[4] );

		$m = new Message;
		$m->parseMessage( $use, $author, $date, $time, $length, STDIN );
		break;
	}

	case "notification_remote_message": {
		$user = argUser( $argv[0] );
		$subject = argId( $argv[1] );
		$author = argId( $argv[2] );
		$seqNum = argNum( $argv[3] );
		$date = argDate( $argv[4] );
		$time = argTime( $argv[5] );
		$length = argLength( $argv[6] );

		$m = new Message;
		$m->parseRemoteMessage( $user, $subject, $author, $seqNum,
				$date, $time, $length, STDIN );
		break;
	}

	case "notification_remote_publication": {
		$user = argUser( $argv[0] );
		$subject = argId( $argv[1] );
		$length = argLength( $argv[2] );

		$m = new Message;
		$m->parseRemotePublication( $user, $subject, $length, STDIN );
		break;
	}
}
?>
