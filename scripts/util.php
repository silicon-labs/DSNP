<?php

# Move to the php directory. */
$dir = str_replace( 'util.php', '', $argv[0] );
chdir( $dir );

$config = $argv[1];
$type = $argv[2];

# Simlate the server environment so that the right installation can be selected.
$_SERVER['HTTP_HOST'] = $argv[1];
$_SERVER['REQUEST_URI'] = $argv[2];
include(dirname(dirname(dirname(__FILE__))) . '/etc/config.php');

if ( !isset( $CFG_URI ) ) {
	echo "could not select configuration\n";
	exit( 1 );
}

$command = $argv[3];
$b = 4;

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

function obtainFriendProof( $user, $identity )
{
	global $CFG_URI;
	global $CFG_PORT;
	global $CFG_COMM_KEY;

	$fp = fsockopen( 'localhost', $CFG_PORT );
	if ( !$fp )
		exit(1);

	$send = 
		"SPP/0.1 $CFG_URI\r\n" . 
		"comm_key $CFG_COMM_KEY\r\n" .
		"obtain_friend_proof $user $identity\r\n";

	fwrite( $fp, $send );
	$res = fgets($fp);
	echo "obtain_friend_proofsend result: $res";
}

function sendRealName( $user )
{
	global $CFG_URI;
	global $CFG_PORT;
	global $CFG_COMM_KEY;

	$query = sprintf(
		"SELECT name FROM user WHERE user = '%s'",
		mysql_real_escape_string($user) );

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	if ( $row = mysql_fetch_assoc($result) ) {
		$name = $row['name'];

		/* User message */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: name-change\r\n" .
			"\r\n";
		$message = $name;
		$len = strlen( $headers ) + strlen( $message );

		$fp = fsockopen( 'localhost', $CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $CFG_URI\r\n" . 
			"comm_key $CFG_COMM_KEY\r\n" .
			"submit_broadcast $user social $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);
		echo "send real name for $user result: $res";
	}
}

function removeFromGroup( $user, $gname, $identity )
{
	global $CFG_URI;
	global $CFG_PORT;
	global $CFG_COMM_KEY;

	$fp = fsockopen( 'localhost', $CFG_PORT );
	if ( !$fp )
		exit(1);

	$send = 
		"SPP/0.1 $CFG_URI\r\n" . 
		"comm_key $CFG_COMM_KEY\r\n" .
		"remove_from_group $user $gname $identity\r\n";

	fwrite( $fp, $send );
	$res = fgets($fp);
	echo "remove_from_group result: $res\n";
}

function addToGroup( $user, $gname, $identity )
{
	global $CFG_URI;
	global $CFG_PORT;
	global $CFG_COMM_KEY;

	$fp = fsockopen( 'localhost', $CFG_PORT );
	if ( !$fp )
		exit(1);

	$send = 
		"SPP/0.1 $CFG_URI\r\n" . 
		"comm_key $CFG_COMM_KEY\r\n" .
		"add_to_group $user $gname $identity\r\n";

	fwrite( $fp, $send );
	$res = fgets($fp);
	echo "add_to_group result: $res\n";
}

$notification_type = $argv[3];
$b = 4;

switch ( $notification_type ) {
case "remove_from_group": {
	$user = $argv[$b+0];
	$group = $argv[$b+1];
	$identity = $argv[$b+2];
	removeFromGroup( $user, $group, $identity );
	break;
}
case "add_to_group": {
	$user = $argv[$b+0];
	$group = $argv[$b+1];
	$identity = $argv[$b+2];
	echo "addToGroup( $user, $group, $identity );\n";
	break;
}
}

?>
