<?php

define( 'DS', DIRECTORY_SEPARATOR );
define( 'ROOT', dirname(__FILE__) );
define( 'PREFIX', dirname(dirname(dirname(ROOT))) );

require( ROOT . "/message.php" );

printf( "NOTIFICATION ARRIVED:\n" );
print_r( $argv );

# Move to the php directory. */
$dir = str_replace( 'notification.php', '', array_shift( $argv ) );
chdir( $dir );

$CFG = NULL;

# Simlate the server environment so that the right installation can be selected.
$_SERVER['HTTP_HOST'] = array_shift( $argv );
$_SERVER['REQUEST_URI'] = array_shift( $argv ) . '/';

require( PREFIX . '/etc/install.php' );
require( PREFIX . '/etc/config.php' );
require( PREFIX . '/share/dsnp/web/database.php' );

$DATA_DIR = PREFIX . "/var/lib/dsnp/{$CFG[NAME]}/data";

$notification_type = array_shift( $argv );

# Connect to the database.
$conn = mysql_connect($CFG[DB_HOST], $CFG[DB_USER], $CFG[DB_PASS]) or die 
	('Could not connect to database');
mysql_select_db($CFG[DB_DATABASE]) or die
	('Could not select database ' . $CFG[DB_DATABASE]);

switch ( $notification_type ) {
	case "notification_broadcast": {
		# Read the message from stdin.
		$m = new Message;
		$m->parseBroadcast( $argv, STDIN );
		break;
	}

	case "notification_message": {
		$m = new Message;
		$m->parseMessage( $argv, STDIN );
		break;
	}

	case "notification_remote_message": {
		$m = new Message;
		$m->parseRemoteMessage( $argv, STDIN );
		break;
	}

	case "notification_remote_publication": {
		$m = new Message;
		$m->parseRemotePublication( $argv, STDIN );
		break;
	}
}
?>
