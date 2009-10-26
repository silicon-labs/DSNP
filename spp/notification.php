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
include("php/app/webroot/config.php");

$notification_type = $argv[3];
$b = 4;

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

switch ( $notification_type ) {
case "direct_broadcast": {
	# Collect the args.
	$type = $argv[$b+0];
	$for_user = $argv[$b+1];
	$author_id = $argv[$b+2];
	$seq_num = $argv[$b+3];
	$date = $argv[$b+4];
	$time = $argv[$b+5];
	$resource_id = $argv[$b+6];
	$length = $argv[$b+7];

	# Read the message from stdin.
	$msg = fread( STDIN, $length );

	if ( strcmp( $type, "PHT" ) == 0 ) {
		$name = sprintf( "pub-%ld.jpg", $seq_num );

		$path = sprintf( "%s/%s/pub-%ld.jpg", $CFG_PHOTO_DIR, $for_user, $seq_num );

		$f = fopen( $path, "wb" );
		fwrite( $f, $msg, $length );
		fclose( $f );

		$msg = $name;
		$length = strlen( $msg );
	}

	$query = sprintf(
		"INSERT INTO received " .
		"	( for_user, author_id, seq_num, time_published, time_received, type, resource_id, message ) " .
		"VALUES ( '%s', '%s', %ld, '%s', now(), '%s', %ld, '%s' )",
		mysql_real_escape_string($for_user), 
		mysql_real_escape_string($author_id), 
		$seq_num, 
		mysql_real_escape_string($date . ' ' . $time),
		mysql_real_escape_string($type),
		$resource_id, 
		mysql_real_escape_string($msg)
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	break;
}
case "remote_broadcast": {
	# Collect the args.
	$type = $argv[$b+0];
	$for_user = $argv[$b+1];
	$subject_id = $argv[$b+2];
	$author_id = $argv[$b+3];
	$seq_num = $argv[$b+4];
	$date = $argv[$b+5];
	$time = $argv[$b+6];
	$length = $argv[$b+7];

	# Read the message from stdin.
	$msg = fread( STDIN, $length );

	printf( "notification %s of %s %s %s %s %s %s %s %s %s\n", 
		$notification_type, $type, $for_user, $subject_id, $author_id, $seq_num,
		$date, $time, $resource_id, $length );

	$query = sprintf(
		"INSERT INTO received " .
		"	( for_user, subject_id, author_id, seq_num, time_published, time_received, ".
		"		type, resource_id, message ) " .
		"VALUES ( '%s', '%s', '%s', %ld, '%s', now(), '%s', %ld, '%s' )",
		mysql_real_escape_string($for_user), 
		mysql_real_escape_string($subject_id), 
		mysql_real_escape_string($author_id), 
		$seq_num, 
		mysql_real_escape_string($date . ' ' . $time),
		mysql_real_escape_string($type),
		$resource_id, 
		mysql_real_escape_string($msg)
	);

	$result = mysql_query($query) or die('Query failed: ' . mysql_error());
	break;
}
case "remote_publication": {
	# Collect the args.
	$type = $argv[$b+0];
	$user = $argv[$b+1];
	$subject_id = $argv[$b+2];
	$author_id = $argv[$b+3];
	$length = $argv[$b+4];

	# Read the message from stdin.
	$msg = fread( STDIN, $length );

	printf( "notification %s of %s %s %s %s %s\n", 
		$notification_type, $type, $user, $subject_id, $author_id, $length );

	$query = sprintf(
		"INSERT INTO remote_published " .
		"	( user, subject_id, author_id, time_published, type, message ) " .
		"VALUES ( '%s', '%s', '%s', now(), '%s', '%s' )",
		mysql_real_escape_string($user), 
		mysql_real_escape_string($subject_id), 
		mysql_real_escape_string($author_id), 
		mysql_real_escape_string($type),
		mysql_real_escape_string($msg)
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
