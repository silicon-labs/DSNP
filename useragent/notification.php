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
		$user = $argv[0];
		$author = $argv[1];
		$seqNum = $argv[2];
		$date = $argv[3];
		$time = $argv[4];
		$length = $argv[5];

		$m = new Message;
		$m->parseBroadcast( $user, $author, $seqNum, $date,
				$time, $length, STDIN );
		break;
	}

	case "notification_message": {
		$user = $argv[0];
		$author = $argv[1];
		$date = $argv[2];
		$time = $argv[3];
		$length = $argv[4];

		$m = new Message;
		$m->parseMessage( $use, $author, $date, $time, $length, STDIN );
		break;
	}

	case "notification_remote_message": {
		$user = $argv[0];
		$subject = $argv[1];
		$author = $argv[2];
		$seqNum = $argv[3];
		$date = $argv[4];
		$time = $argv[5];
		$length = $argv[6];

		$m = new Message;
		$m->parseRemoteMessage( $user, $subject, $author, $seqNum,
				$date, $time, $length, STDIN );
		break;
	}

	case "notification_remote_publication": {
		$user = $argv[0];
		$subject = $argv[1];
		$length = $argv[2];

		$m = new Message;
		$m->parseRemotePublication( $user, $subject, $length, STDIN );
		break;
	}
}
?>
