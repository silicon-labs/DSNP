<?php

printf( "Running Secret Santa\n" );

# Move to the php directory. */
$dir = str_replace( 'runss.php', '', $argv[0] );
chdir( $dir );

$config = $argv[1];
$type = $argv[2];

# Simlate the server environment so that the right installation can be selected.
$_SERVER['HTTP_HOST'] = $argv[1];
$_SERVER['REQUEST_URI'] = $argv[2];
include(dirname(dirname(dirname(dirname(__FILE__)))) . '/etc/config.php');

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);


$badMatch = array(
	'https://www.anemonal.ca/Suzanne/' => 'https://www.anemonal.ca/Grandpa/',
	'https://www.anemonal.ca/Grandpa/' => 'https://www.anemonal.ca/Suzanne/',
	'https://www.anemonal.ca/Soojinpark/' => 'https://www.anemonal.ca/Gomethrius/',
	'https://www.anemonal.ca/Gomethrius/' => 'https://www.anemonal.ca/Soojinpark/' ,
	'https://www.anemonal.ca/Anne/' => 'https://www.anemonal.ca/Chris/',
	'https://www.anemonal.ca/Chris/' => 'https://www.anemonal.ca/Anne/'
);


$query = "SELECT id, identity FROM friend_claim WHERE user_id = 4;";
$result = mysql_query($query) or die('Query failed: ' . mysql_error());
while ( $row = mysql_fetch_assoc($result) )
	$people[$row['identity']] =  $row['id'];

function randomize( $people )
{
	$senders = $people;
	$recipients = $people;
	foreach ( $senders as $from => $fromId ) {
		$size = count( $recipients );
		$get = rand() % $size;
		$i = 0;
		foreach ( $recipients as $to => $id ) {
			if ( $i++ == $get ) {
				unset( $recipients[$to] );
				$gives[$from] = $to;
				break;
			}
		}
	}
	return $gives;
}

function bad( $gives ) 
{
	global $badMatch;
	foreach ( $gives as $from => $to ) {
		if ( $from === $to ){
			printf("bad match $from == $to\n");
			return true;
		}
		if ( isset($badMatch[$from]) && $badMatch[$from] === $to ) {
			printf("bad match $from => $to\n");
			return true;
		}
	}
	return false;
}

while ( true ) {
	$gives = randomize($people);
	if ( !bad( $gives ) )
		break;
}
print_r($gives);

$query = "DELETE FROM secret_santa;";
$result = mysql_query($query) or die('Query failed: ' . mysql_error());

foreach ( $gives as $from => $to ) {
	$fromId = $people[$from];
	$toId = $people[$to];
	$query = "INSERT INTO secret_santa ( friend_id, gives_to_id ) VALUES ( $fromId, $toId );";
	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	
}

