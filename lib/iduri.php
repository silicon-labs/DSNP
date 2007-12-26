<?php

/* 
 * Copyright (c) 2007, Adrian Thurston <thurston@cs.queensu.ca>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

putenv( 'GNUPGHOME=./gnupghome/' );
$HTTP_GET_TIMEOUT = 5;

function iduriSessionStart()
{
	global $IDENTITY
	$path = preg_replace( "/^http:\/\/[^\/]*/", "", $IDENTITY );
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

function importId( $gnupg, $uri, $timeout )
{
	$response = http_get( $uri . 'id.asc', array("timeout"=>$timeout), $info );
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

function encryptSign( $gnupg, $to_fp, $message )
{
	global $FINGERPRINT;
	$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
	$gnupg->addencryptkey( $to_fp );
	$gnupg->addsignkey( $FINGERPRINT, '' );
	return $gnupg->encryptsign( $message );
}

function publishMessage( $prefix, $name, $message )
{
	$fn = $prefix . '/' . $name . '.asc';
	$fd = fopen( $fn, 'wt' );
	fwrite( $fd, $message );
	fclose( $fd );
	chmod( $fn, 0644 );
}

function writeData( $data )
{
	$fd = fopen( 'data.srl', 'w' );	
	$s = serialize( $data );
	fprintf( $fd, "%d\n", strlen( $s ) );
	fwrite( $fd, $s );
	fprintf( $fd, "\n" );
}

function readData( )
{
	$fd = fopen( 'data.srl', 'r' );	
	fscanf( $fd, "%d\n", &$slen  );
	$s = fread( $fd, $slen );
	return unserialize( $s );
}

function friendList( $data )
{
	$owner = $_SESSION['auth'] == 'owner';
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
		if ( $owner ) {
			echo "<a href=\"refresh.php?uri=" . urlencode($uri) . "\">refresh</a>";
		}
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
