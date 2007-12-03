<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

$token = $_GET['token'];

$data = read_data( );
$friends = $data['friends'];

if ( $_SESSION['tok'] == $token ) {
	$_SESSION['auth'] = 'friend';
	header( "Location: $IDENTITY" );
}
else {
	echo "<center>\n";
	echo "FRIEND LOGIN FAILED<br>\n";
	friendLoginForm();
	echo "</center>\n";
}
