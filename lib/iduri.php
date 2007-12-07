<?php

putenv( 'GNUPGHOME=./gnupghome/' );

function iduri_session_start( $id )
{
	$path = preg_replace( "/^http:\/\/[^\/]*/", "", $id );
	session_set_cookie_params( 0, $path );
	session_start();
}

function loginForm()
{
	?><form method="post" action="submitlogin.php">
	Owner Login to Iduri:
	<input type="text" name="username">
	<input type="password" name="password">
	<input type="submit">
	</form><?php
}

function friendLoginForm()
{
	?><form method="post" action="submitflogin.php">
	Friend Login to Iduri:
	<input type="text" size=70 name="uri">
	<input type="submit">
	</form><?php
}

function import_id( $gnupg, $URI )
{
	$response = http_get( $URI . 'id.asc', array("timeout"=>1), $info );
	$message = http_parse_message( $response );

	// Import the key.
	$res = $gnupg->import( $message->body );

	$fp = $res['fingerprint'];
	$res = $gnupg->keyinfo( '0x' . $fp );

	/* Need to verify what is returned. If it fails then delete it. */
	$uid = $res[0]['uids'][0];
	$user_id = $uid['uid'];

	//header('Content-type: text/plain');
	return $fp;
}

function sign( $gpg )
{
	$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
	$gnupg->addsignkey( $FINGERPRINT, "" );
	return $gnupg->sign( $IDENTITY );
}

function write_data( $data )
{
	$fd = fopen( 'data.srl', 'w' );	
	$s = serialize( $data );
	fprintf( $fd, "%d\n", strlen( $s ) );
	fwrite( $fd, $s );
	fprintf( $fd, "\n" );
}

function read_data( )
{
	$fd = fopen( 'data.srl', 'r' );	
	fscanf( $fd, "%d\n", &$slen  );
	$s = fread( $fd, $slen );
	return unserialize( $s );
}

function initDB()
{
	$data = Array(
		'name' => '',
		'friends' => Array()
	);

	write_data( $data );
}

function friendList( $data )
{
	$friends = $data['friends'];
	foreach ( $friends as $uri => $fp ) {
		echo "<a href=\"$uri\">$uri</a> ";
		$fn = 'downloads/' . $fp . '.srl';
		if ( is_file( $fn ) ) {
			$fd = fopen( $fn, 'r' );
			fclose( $fd );
			echo "have data ";
		}
		else {
			echo "no data ";
		}
		echo "<a href=\"refresh.php?uri=" . urlencode($uri) . "\">refresh</a>";
		echo "<br>";
	}
}

function showFriendRequests( $data )
{
	$requests = $data['requests'];
	foreach ( $requests as $furi => $n ) {
		echo "<b>Friend Request:</b> <a href=\"$furi\">$furi</a>&nbsp;&nbsp;<a\n";
		echo "href=\"answer.php?uri=" . urlencode($furi) . "&a=yes\">yes</a>&nbsp;&nbsp;<a\n";
		echo "href=\"answer.php?uri=" . urlencode($furi) . "&a=no\">no</a><br>\n";
	}
}

function requireFriend()
{
	if ( $_SESSION['auth'] != 'friend' )
		exit("You do not have permission to access this page\n");
}

function requireOwner()
{
	if ( $_SESSION['auth'] != 'owner' )
		exit("You do not have permission to access this page\n");
}

?>
