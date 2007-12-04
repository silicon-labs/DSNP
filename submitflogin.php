<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

$furi = $_POST['uri'];

$data = read_data( );
$friends = $data['friends'];
$putrelids = $data['putrelids'];

if ( !isset( $friends[$furi] ) ) {
	echo "<center>\n";
	echo "Not a friend of mine<br><br>\n";
	friendLoginForm();
	echo "</center>\n";
}
else {
	$gnupg = new gnupg();
	$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
	$gnupg->addencryptkey( $friends[$furi] );
	$gnupg->addsignkey( $FINGERPRINT, '' );
	$token = sha1( uniqid( mt_rand() ) );
	$_SESSION['tok'] = $token;
	$enc = $gnupg->encryptsign( $token );
	$fn = 'tokens/' . $putrelids[$friends[$furi]] . '.asc';
	$fd = fopen( $fn, 'wt' );
	fwrite( $fd, $enc );
	fclose( $fd );
	chmod( $fn, 0644 );


	header('Location: ' . $furi . 'returnftok.php?uri=' . urlencode( $IDENTITY ) );
}
