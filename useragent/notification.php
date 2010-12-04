<?php

define( 'DS', DIRECTORY_SEPARATOR );
define( 'ROOT', dirname(__FILE__) );
define( 'PREFIX', dirname(dirname(dirname(ROOT))) );

require( ROOT . "/message.php" );

printf( "NOTIFICATION ARRIVED:\n" );
print_r( $argv );

# Move to the php directory. */
$dir = str_replace( 'notification.php', '', $argv[0] );
chdir( $dir );

$CFG = NULL;

# Simlate the server environment so that the right installation can be selected.
$_SERVER['HTTP_HOST'] = $argv[1];
$_SERVER['REQUEST_URI'] = $argv[2] . '/';

require( PREFIX . '/etc/install.php' );
require( PREFIX . '/etc/config.php' );
require( PREFIX . '/share/dsnp/web/database.php' );

$DATA_DIR = PREFIX . "/var/lib/dsnp/{$CFG[NAME]}/data";

$notification_type = $argv[3];
$b = 4;

# Connect to the database.
$conn = mysql_connect($CFG[DB_HOST], $CFG[DB_USER], $CFG[ADMIN_PASS]) or die 
	('Could not connect to database');
mysql_select_db($CFG[DB_DATABASE]) or die
	('Could not select database ' . $CFG[DB_DATABASE]);

function user_name_from_id( $identity )
{
	return preg_replace( '/https:\/\/.*\/([^\/]*)\//', '$1', $identity );
}

function findFriendClaimId( $user, $identity )
{
	$result = dbQuery(
		"SELECT friend_claim.id FROM friend_claim " .
		"JOIN user ON user.id = friend_claim.user_id " .
		"WHERE user.user = %e AND friend_claim.friend_id = %e",
		$user,
		$identity
	);

	if ( count( $result ) == 1 )
		return (int) $result[0]['id'];
	return -1;
}

function findUserId( $user )
{
	$results = dbQuery(
		"SELECT id FROM user WHERE user.user = %e",
		$user
	);

	if ( count( $results ) == 1 )
		return (int) $results[0]['id'];
	return -1;
}

function photoUpload( $for_user, $network, $author, $seq_num, $date, $time, $msg, $content_type )
{
	global $DATA_DIR;

	/* Need a resource id. */
	if ( !isset( $msg[0]['resource-id'] ) )
		return;

	$local_resid = $seq_num;
	$remote_resid = (int) $msg[0]['resource-id'];

	$user_id = findUserId( $for_user );
	$author_id = findFriendClaimId( $for_user, $author );

	/* The message body is photo data. Write the photo to disk. */
	$path = sprintf( "%s/%s/pub-%ld.jpg", $DATA_DIR, $for_user, $seq_num );

	$length = strlen( $msg[1] );
	$f = fopen( $path, "wb" );
	fwrite( $f, $msg[1], $length );
	fclose( $f );

	$name = sprintf( "pub-%ld.jpg", $seq_num );

	dbQuery(
		"INSERT INTO activity " .
		"	( user_id, author_id, seq_num, time_published, " . 
		"		time_received, type, local_resid, remote_resid, message ) " .
		"VALUES ( %l, %l, %l, %e, now(), %e, %l, %l, %e )",
		$user_id,
		$author_id, 
		$seq_num, 
		$date . ' ' . $time,
		'PHT',
		$local_resid, 
		$remote_resid, 
		$name
	);
}

function nameChange( $for_user, $author_id, $seq_num, $date, $time, $msg, $content_type )
{
	if ( $content_type != 'text/plain' )
		return;

	$result = dbQuery( "SELECT id FROM user WHERE user = %e", $for_user );

	if ( count( $result ) === 1 ) {
		$user = $result[0];
		dbQuery( 
			"UPDATE friend_claim SET name = %e " . 
			"WHERE user_id = %L AND friend_id = %e",
			$msg[1], $user['id'], $author_id );
	}
}

function broadcast( $for_user, $network, $author, $seq_num, $date, $time, $msg, $content_type )
{
	/* Need a resource id. */
	if ( $content_type != 'text/plain' )
		return;

	$user_id = findUserId( $for_user );
	$author_id = findFriendClaimId( $for_user, $author );

	dbQuery(
		"INSERT INTO activity " .
		"	( user_id, author_id, seq_num, time_published, " . 
		"		time_received, type, message ) " .
		"VALUES ( %l, %l, %l, %e, now(), %e, %e )",
		$user_id, $author_id,
		$seq_num, $date . ' ' . $time,
		'MSG', $msg[1]
	);
}


function boardPost( $for_user, $network, $subject, $author,
		$seq_num, $date, $time, $msg, $content_type )
{
	$user_id = findUserId( $for_user );
	$subject_id = findFriendClaimId( $for_user, $subject );
	$author_id = findFriendClaimId( $for_user, $author );

	printf("boardPost( $for_user, $network, $subject, " .
			"$author, $seq_num, $date, $time, $msg, $content_type )\n" );

	dbQuery(
		"INSERT INTO activity " .
		"	( user_id, subject_id, author_id, seq_num, time_published, time_received, ".
		"		type, message ) " .
		"VALUES ( %l, %l, %l, %l, %e, now(), %e, %e )",
		$user_id,
		$subject_id, 
		$author_id, 
		$seq_num, 
		$date . ' ' . $time,
		'BRD',
		$msg[1]
	);
}

function remoteBoardPost( $user, $network, $subject, $msg, $content_type )
{
	printf( "function remoteBoardPost( $user, $network, " .
			"$subject, $msg, $content_type )\n" );

	$user_id = findUserId( $user );
	$subject_id = findFriendClaimId( $user, $subject );

	dbQuery(
		"INSERT INTO activity " .
		"	( user_id, subject_id, published, time_published, type, message ) " .
		"VALUES ( %l, %l, %l, true, now(), %e, %e )",
		$user_id,
		$subject_id, 
		'BRD',
		$msg[1]
	);
}

switch ( $notification_type ) {
case "user_message": {
	# Collect the args.
	$for_user = $argv[$b+0];
	$network = $argv[$b+1];
	$subject = $argv[$b+2];
	$author = $argv[$b+3];
	$seq_num = $argv[$b+4];
	$date = $argv[$b+5];
	$time = $argv[$b+6];
	$length = $argv[$b+7];

	if ( $network === '-' )
		$network = null;
	if ( $subject === '-' )
		$subject = null;

	# Read the message from stdin.
	$message = new Message;
	$msg = $message->parse( STDIN, $length );

	if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
		$type = $msg[0]['type'];
		$content_type = $msg[0]['content-type'];
		print("type: $type\n" );
		print("content-type: $content_type\n" );

		switch ( $type ) {
			case 'name-change':
				nameChange( $for_user, $author, $seq_num, 
						$date, $time, $msg, $content_type );
				break;
			case 'photo-upload':
				photoUpload( $for_user, $network, $author,
						$seq_num, $date, $time, $msg, $content_type );
				break;
			case 'broadcast':
				broadcast( $for_user, $network, $author,
						$seq_num, $date, $time, $msg, $content_type );
				break;
			case 'board-post':
				boardPost( $for_user, $network, $subject, $author, $seq_num,
						$date, $time, $msg, $content_type );
				break;
		}
	}
	break;
}

case "remote_publication": {
	# Collect the args.
	$user = $argv[$b+0];
	$network = $argv[$b+1];
	$subject = $argv[$b+2];
	$length = $argv[$b+3];

	# Read the message from stdin.
	$message = new Message;
	$msg = $message->parse( STDIN, $length );

	if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
		$type = $msg[0]['type'];
		$content_type = $msg[0]['content-type'];
		print("type: $type\n" );
		print("content-type: $content_type\n" );

		switch ( $type ) {
			case 'board-post':
				remoteBoardPost( $user, $network, $subject, $msg, $content_type );
				break;
		}
	}
	break;
}
}
?>
