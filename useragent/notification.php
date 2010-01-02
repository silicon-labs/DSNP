<?php

printf( "NOTIFICATION ARRIVED:\n" );
print_r( $argv );

# Move to the php directory. */
$dir = str_replace( 'notification.php', '', $argv[0] );
chdir( $dir );

$config = $argv[1];
$type = $argv[2];

# Simlate the server environment so that the right installation can be selected.
$_SERVER['HTTP_HOST'] = $argv[1];
$_SERVER['REQUEST_URI'] = $argv[2];
include(dirname(dirname(dirname(dirname(__FILE__)))) . '/etc/config.php');

$notification_type = $argv[3];
$b = 4;

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

function user_name_from_id( $identity )
{
	return preg_replace( '/https:\/\/.*\/([^\/]*)\//', '$1', $identity );
}

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

function findFriendClaimId( $user, $identity )
{
	$query = sprintf(
		"SELECT friend_claim.id FROM friend_claim " .
		"JOIN user ON user.id = friend_claim.user_id " .
		"WHERE user.user = '%s' AND friend_claim.identity = '%s'",
		mysql_real_escape_string($user),
		mysql_real_escape_string($identity)
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	if ( $row = mysql_fetch_assoc($result) )
		return (int) $row['id'];
	return -1;
}

function findUserId( $user )
{
	$query = sprintf(
		"SELECT id FROM user WHERE user.user = '%s'",
		mysql_real_escape_string($user)
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	if ( $row = mysql_fetch_assoc($result) )
		return (int) $row['id'];
	return -1;
}

function photoUpload( $for_user, $author, $seq_num, $date, $time, $msg, $content_type )
{
	global $CFG_PHOTO_DIR;

	/* Need a resource id. */
	if ( !isset( $msg[0]['resource-id'] ) )
		return;

	$local_resid = $seq_num;
	$remote_resid = (int) $msg[0]['resource-id'];
	$user_id = findUserId( $for_user );
	$author_id = findFriendClaimId( $for_user, $author );

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
		$remote_resid, 
		mysql_real_escape_string($name)
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());

	$query = sprintf(
		"INSERT INTO activity " .
		"	( user_id, author_id, seq_num, time_published, " . 
		"		time_received, type, local_resid, remote_resid, message ) " .
		"VALUES ( '%s', %ld, %ld, '%s', now(), '%s', %ld, %ld, '%s' )",
		$user_id,
		$author_id, 
		$seq_num, 
		mysql_real_escape_string($date . ' ' . $time),
		mysql_real_escape_string('PHT'),
		$local_resid, 
		$remote_resid, 
		mysql_real_escape_string($name)
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
}

function nameChange( $for_user, $author_id, $seq_num, $date, $time, $msg, $content_type )
{
	if ( $content_type != 'text/plain' )
		return;

	$query = sprintf(
		"SELECT id FROM user WHERE user = '%s'",
		mysql_real_escape_string($for_user) );
	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	if ( $row = mysql_fetch_assoc($result) ) {
		$query = sprintf(
			"UPDATE friend_claim SET name = '%s' " .
			"WHERE user_id = %ld AND identity = '%s'",
			mysql_real_escape_string($msg[1]),
			mysql_real_escape_string($row['id']), 
			mysql_real_escape_string($author_id) 
		);

		$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	}
}

function broadcast( $for_user, $author, $seq_num, $date, $time, $msg, $content_type )
{
	/* Need a resource id. */
	if ( $content_type != 'text/plain' )
		return;

	$user_id = findUserId( $for_user );
	$author_id = findFriendClaimId( $for_user, $author );

	$query = sprintf(
		"INSERT INTO received " .
		"	( for_user, author_id, subject_id, seq_num, time_published, " . 
		"		time_received, type, message ) " .
		"VALUES ( '%s', %ld, %ld, %ld, '%s', now(), '%s', '%s' )",
		mysql_real_escape_string($for_user), 
		$author_id,
		$author_id,
		$seq_num, 
		mysql_real_escape_string($date . ' ' . $time),
		mysql_real_escape_string('MSG'),
		mysql_real_escape_string($msg[1])
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());

	$query = sprintf(
		"INSERT INTO activity " .
		"	( user_id, author_id, seq_num, time_published, " . 
		"		time_received, type, message ) " .
		"VALUES ( '%s', %ld, %ld, '%s', now(), '%s', '%s' )",
		$user_id,
		$author_id,
		$seq_num, 
		mysql_real_escape_string($date . ' ' . $time),
		mysql_real_escape_string('MSG'),
		mysql_real_escape_string($msg[1])
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
}


function boardPost( $for_user, $subject, $author, $seq_num, $date, $time, $msg, $content_type )
{
	$user_id = findUserId( $for_user );
	$subject_id = findFriendClaimId( $for_user, $subject );
	$author_id = findFriendClaimId( $for_user, $author );

	printf("board post with subject %ld and author %ld\n", $subject_id, $author_id );

	$query = sprintf(
		"INSERT INTO received " .
		"	( for_user, subject_id, author_id, seq_num, time_published, time_received, ".
		"		type, message ) " .
		"VALUES ( '%s', %ld, %ld, %ld, '%s', now(), '%s', '%s' )",
		mysql_real_escape_string($for_user), 
		$subject_id, 
		$author_id, 
		$seq_num, 
		mysql_real_escape_string($date . ' ' . $time),
		mysql_real_escape_string('BRD'),
		mysql_real_escape_string($msg[1])
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());

	$query = sprintf(
		"INSERT INTO activity " .
		"	( user_id, subject_id, author_id, seq_num, time_published, time_received, ".
		"		type, message ) " .
		"VALUES ( '%s', %ld, %ld, %ld, '%s', now(), '%s', '%s' )",
		$user_id,
		$subject_id, 
		$author_id, 
		$seq_num, 
		mysql_real_escape_string($date . ' ' . $time),
		mysql_real_escape_string('BRD'),
		mysql_real_escape_string($msg[1])
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
}

function remoteBoardPost( $user, $subject, $msg, $content_type )
{
	$user_id = findUserId( $user );
	$subject_id = findFriendClaimId( $user, $subject );

	$query = sprintf(
		"INSERT INTO remote_published " .
		"	( user, subject_id, time_published, type, message ) " .
		"VALUES ( '%s', %ld, now(), '%s', '%s' )",
		mysql_real_escape_string($user), 
		$subject_id, 
		mysql_real_escape_string('BRD'),
		mysql_real_escape_string($msg[1])
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());

	$query = sprintf(
		"INSERT INTO activity " .
		"	( user_id, subject_id, published, time_published, type, message ) " .
		"VALUES ( '%s', %ld, true, now(), '%s', '%s' )",
		$user_id,
		$subject_id, 
		mysql_real_escape_string('BRD'),
		mysql_real_escape_string($msg[1])
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
}

function sendRealName( $user, $toIdentity )
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

		if ( isset( $name ) && strlen( $name ) > 0 ) {
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
				"submit_message $user $toIdentity $len\r\n";

			fwrite( $fp, $send );
			fwrite( $fp, $headers, strlen($headers) );
			fwrite( $fp, $message, strlen($message) );
			fwrite( $fp, "\r\n", 2 );

			$res = fgets($fp);
			echo "send real name result: $res";
		}
	}
}

function friendProof( $user, $group, $subject, $author, $seq_num, $date, $time )
{
	$user_id = findUserId( $user );
	$subject_id = findFriendClaimId( $user, $subject );
	$author_id = findFriendClaimId( $user, $author );

	$query = sprintf(
		"INSERT INTO friend_link " .
		"	( group_name, fc1_id, fc2_id ) " .
		"VALUES ( '%s', %ld, %ld ) ",
		mysql_real_escape_string( $group ),
		$author_id,
		$subject_id 
	);

	/* Allow this query to fail due to duplicates. */
	mysql_query($query) or die('Query failed: ' . mysql_error());
}

function groupMemberRevocation( $user, $friend, $group, $generation, $revoked )
{
	echo "group member revocation: $user $friend $group $generation $revoked\n";

	$userId = findUserId( $user );
	$friendId = findFriendClaimId( $user, $friend );
	$revokedId = findFriendClaimId( $user, $revoked );

	$query = sprintf(
		"DELETE FROM friend_link " .
		"WHERE fc1_id = %ld AND fc2_id = %ld AND group_name = '%s' ",
		$friendId,
		$revokedId ,
		mysql_real_escape_string( $group )
	);

	/* Allow this query to fail due to duplicates. */
	mysql_query($query) or die('Query failed: ' . mysql_error());
}

switch ( $notification_type ) {
case "user_message": {
	# Collect the args.
	$for_user = $argv[$b+0];
	$subject = $argv[$b+1];
	$author = $argv[$b+2];
	$seq_num = $argv[$b+3];
	$date = $argv[$b+4];
	$time = $argv[$b+5];
	$length = $argv[$b+6];

	if ( $subject === '-' )
		$subject = null;

	# Read the message from stdin.
	$msg = parse( $length );

	if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
		$type = $msg[0]['type'];
		$content_type = $msg[0]['content-type'];
		print("type: $type\n" );
		print("content-type: $content_type\n" );

		switch ( $type ) {
			case 'name-change':
				nameChange( $for_user, $author, $seq_num, $date, $time, $msg, $content_type );
				break;
			case 'photo-upload':
				photoUpload( $for_user, $author, $seq_num, $date, $time, $msg, $content_type );
				break;
			case 'broadcast':
				broadcast( $for_user, $author, $seq_num, $date, $time, $msg, $content_type );
				break;
			case 'board-post':
				boardPost( $for_user, $subject, $author, $seq_num,
						$date, $time, $msg, $content_type );
				break;
		}
	}
	break;
}

case "remote_publication": {
	# Collect the args.
	$user = $argv[$b+0];
	$subject = $argv[$b+1];
	$length = $argv[$b+2];

	# Read the message from stdin.
	$msg = parse( $length );

	if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
		$type = $msg[0]['type'];
		$content_type = $msg[0]['content-type'];
		print("type: $type\n" );
		print("content-type: $content_type\n" );

		switch ( $type ) {
			case 'board-post':
				remoteBoardPost( $user, $subject, $msg, $content_type );
				break;
		}
	}
	break;
}

case "group_member_revocation": {
	# Collect the args.
	$user = $argv[$b+0];
	$friendId = $argv[$b+1];
	$group = $argv[$b+2];
	$generation = $argv[$b+3];
	$revokedId = $argv[$b+4];

	groupMemberRevocation( $user, $friendId, $group, $generation, $revokedId );
	break;
}


case "sent_friend_request": {
	# Collect the args.
	$from_user = $argv[$b+0];
	$for_id = $argv[$b+1];
	break;
}

case "friend_request": {
	# Collect the args.
	$for_user = $argv[$b+0];
	$from_id = $argv[$b+1];
	$user_reqid = $argv[$b+2];
	$requested_relid = $argv[$b+3];
	$returned_relid = $argv[$b+4];

	break;
}

case "sent_friend_request_accepted": {
	$user = $argv[$b+0];
	$identity = $argv[$b+1];

	#sendRealName( $user, $identity );
	break;
}

case "friend_request_accepted": {
	$user = $argv[$b+0];
	$identity = $argv[$b+1];

	#sendRealName( $user, $identity );
	break;
}

case "send_real_name": {
	$user = $argv[$b+0];
	$identity = $argv[$b+1];
	#sendRealName( $user, $identity );
	break;
}
	
}
?>
