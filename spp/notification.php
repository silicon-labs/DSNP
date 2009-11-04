<?php

printf( "NOTIFICATION ARRIVED:\n" );
print_r( $argv );

# Move to the php directory. */
$dir = str_replace( "notification.php", "php", $argv[0] );
chdir( $dir );

$config = $argv[1];
$type = $argv[2];

# Simlate the server environment so that the right installation can be selected.
$_SERVER['HTTP_HOST'] = $argv[1];
$_SERVER['REQUEST_URI'] = $argv[2];
include("php/app/config/config.php");

$notification_type = $argv[3];
$b = 4;

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

function parse( $len )
{
	$headers = array();
	$left = $len;
	while ( true ) {
		$line = fgets( STDIN );
		if ( $line === "\r\n" ) {
			$left -= 2;
			break;
		}
		$left -= strlen( $line );

		/* Parse headers. */
		$replaced = preg_replace( '/Content-Type:[\t ]*/i', '', $line );
		if ( $replaced !== $line )
			$headers['content-type'] = trim($replaced);

		$replaced = preg_replace( '/Resource-Id:[\t ]*/i', '', $line );
		if ( $replaced !== $line )
			$headers['resource-id'] = trim($replaced);

		$replaced = preg_replace( '/Type:[\t ]*/i', '', $line );
		if ( $replaced !== $line )
			$headers['type'] = trim($replaced);

		if ( $left <= 0 )
			break;
	}
	$msg = fread( STDIN, $left );
	return array( $headers, $msg );
}

function photoUpload( $for_user, $author_id, $seq_num, $date, $time, $msg, $content_type )
{
	global $CFG_PHOTO_DIR;

	/* Need a resource id. */
	if ( !isset( $msg[0]['resource-id'] ) )
		return;

	$resource_id = (int) $msg[0]['resource-id'];

	print( "message is a photo, capturing\n" );

	/* The message body is photo data. Write the photo to disk. */
	$path = sprintf( "%s/%s/pub-%ld.jpg", $CFG_PHOTO_DIR, $for_user, $seq_num );

	$length = strlen( $msg[1] );
	$f = fopen( $path, "wb" );
	fwrite( $f, $msg[1], $length );
	fclose( $f );

	$name = sprintf( "pub-%ld.jpg", $seq_num );

	$query = sprintf(
		"INSERT INTO received " .
		"	( for_user, author_id, seq_num, time_published, " . 
		"		time_received, type, resource_id, message ) " .
		"VALUES ( '%s', '%s', %ld, '%s', now(), '%s', %ld, '%s' )",
		mysql_real_escape_string($for_user), 
		mysql_real_escape_string($author_id), 
		$seq_num, 
		mysql_real_escape_string($date . ' ' . $time),
		mysql_real_escape_string('PHT'),
		$resource_id, 
		mysql_real_escape_string($name)
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
}

function nameChange( $for_user, $author_id, $seq_num, $date, $time, $msg, $content_type )
{
	if ( $content_type != 'text/plain' )
		return;

	$query = sprintf(
		"UPDATE friend_claim SET name = '%s' WHERE user = '%s' AND friend_id = '%s' ",
		mysql_real_escape_string($msg[1]),
		mysql_real_escape_string($for_user), 
		mysql_real_escape_string($author_id) 
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
}

function broadcast( $for_user, $author_id, $seq_num, $date, $time, $msg, $content_type )
{
	/* Need a resource id. */
	if ( $content_type != 'text/plain' )
		return;

	$query = sprintf(
		"INSERT INTO received " .
		"	( for_user, author_id, seq_num, time_published, " . 
		"		time_received, type, resource_id, message ) " .
		"VALUES ( '%s', '%s', %ld, '%s', now(), '%s', %ld, '%s' )",
		mysql_real_escape_string($for_user), 
		mysql_real_escape_string($author_id), 
		$seq_num, 
		mysql_real_escape_string($date . ' ' . $time),
		mysql_real_escape_string('MSG'),
		0,
		mysql_real_escape_string($msg[1])
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
}


function boardPost( $for_user, $subject_id, $author_id, $seq_num, $date, $time, $msg, $content_type )
{
	$query = sprintf(
		"INSERT INTO received " .
		"	( for_user, subject_id, author_id, seq_num, time_published, time_received, ".
		"		type, message ) " .
		"VALUES ( '%s', '%s', '%s', %ld, '%s', now(), '%s', '%s' )",
		mysql_real_escape_string($for_user), 
		mysql_real_escape_string($subject_id), 
		mysql_real_escape_string($author_id), 
		$seq_num, 
		mysql_real_escape_string($date . ' ' . $time),
		mysql_real_escape_string('BRD'),
		mysql_real_escape_string($msg[1])
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
}



switch ( $notification_type ) {
case "user_message": {
	# Collect the args.
	$for_user = $argv[$b+0];
	$subject_id = $argv[$b+1];
	$author_id = $argv[$b+2];
	$seq_num = $argv[$b+3];
	$date = $argv[$b+4];
	$time = $argv[$b+5];
	$length = $argv[$b+6];

	if ( $subject_id === '-' )
		$subject_id = null;

	# Read the message from stdin.
	$msg = parse( $length );

	if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
		$type = $msg[0]['type'];
		$content_type = $msg[0]['content-type'];
		print("type: $type\n" );
		print("content-type: $content_type\n" );

		switch ( $type ) {
			case 'photo-upload':
				photoUpload( $for_user, $author_id, $seq_num, $date, $time, $msg, $content_type );
				break;
			case 'name-change':
				nameChange( $for_user, $author_id, $seq_num, $date, $time, $msg, $content_type );
				break;
			case 'broadcast':
				broadcast( $for_user, $author_id, $seq_num, $date, $time, $msg, $content_type );
				break;
			case 'board-post':
				boardPost( $for_user, $subject_id, $author_id, $seq_num, $date, $time, 
						$msg, $content_type );
				break;
		}
	}
	break;
}

case "remote_publication": {
	# Collect the args.
	$user = $argv[$b+0];
	$subject_id = $argv[$b+1];
	$author_id = $argv[$b+2];
	$length = $argv[$b+3];

	# Read the message from stdin.
	$msg = parse( $length );

	$type = 'UKN';
	if ( isset( $msg[0]['type'] ) )
		$type = $msg[0]['type'];
	if ( $type == 'board-post' )
		$type = 'BRD';

	$resource_id = 0;
	if ( isset( $msg[0]['resource-id'] ) )
		$resource_id = (int) $msg[0]['resource-id'];

	$query = sprintf(
		"INSERT INTO remote_published " .
		"	( user, subject_id, author_id, time_published, type, message ) " .
		"VALUES ( '%s', '%s', '%s', now(), '%s', '%s' )",
		mysql_real_escape_string($user), 
		mysql_real_escape_string($subject_id), 
		mysql_real_escape_string($author_id), 
		mysql_real_escape_string($type),
		mysql_real_escape_string($msg[1])
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	break;
}

case "sent_friend_request": {
	# Collect the args.
	$from_user = $argv[$b+0];
	$for_id = $argv[$b+1];

	$query = sprintf(
		"INSERT INTO sent_friend_request " .
		"	( from_user, for_id ) " .
		"VALUES ( '%s', '%s' )",
		mysql_real_escape_string($from_user), 
		mysql_real_escape_string($for_id)
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	break;
}
case "sent_friend_request_accepted": {
	$user = $argv[$b+0];
	$identity = $argv[$b+1];

	$query = sprintf(
		"INSERT INTO friend_claim ( user, friend_id ) " .
		" VALUES ( '%s', '%s' ) ", $user, $identity );

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());

	$query = sprintf(
		"DELETE FROM sent_friend_request " .
		"WHERE from_user = '%s' AND for_id = '%s'",
		mysql_real_escape_string($user), 
		mysql_real_escape_string($identity)
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	break;
}
case "friend_request": {
	# Collect the args.
	$for_user = $argv[$b+0];
	$from_id = $argv[$b+1];
	$user_reqid = $argv[$b+2];
	$requested_relid = $argv[$b+3];
	$returned_relid = $argv[$b+4];

	$query = sprintf(
		"INSERT INTO friend_request " .
		" ( for_user, from_id, reqid, requested_relid, returned_relid ) " .
		" VALUES ( '%s', '%s', '%s', '%s', '%s' ) ",
		$for_user, $from_id, $user_reqid, $requested_relid, $returned_relid);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	break;
}
case "friend_request_accepted": {
	$user = $argv[$b+0];
	$identity = $argv[$b+1];

	$query = sprintf(
		"INSERT INTO friend_claim ( user, friend_id ) " .
		" VALUES ( '%s', '%s' ) ", $user, $identity );

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	break;
}}
?>
