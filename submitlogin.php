<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

$login = $_POST['username'];
$pass = $_POST['password'];
$md5pass = md5( $login . ':iduri:' . $pass );

if ( $login == $USER && $md5pass == $PASS ) {
	/* Login successful. */
	$_SESSION['auth'] = 'owner';
	header( "Location: $IDENTITY" );
}
else {
	echo "<center>\n";
	echo "LOGIN FAILED<br><br>\n";
	loginForm();
	echo "</center>\n";
}
?>
