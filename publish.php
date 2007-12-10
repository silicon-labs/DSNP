<?php

include( 'config.php' );
include( 'lib/iduri.php' );

iduri_session_start( $IDENTITY );

requireOwner();

$data = read_data();

$friends = $data['friends'];
$putrelids = $data['putrelids'];

foreach ( $friends as $uri => $fp ) {
	$gnupg = new gnupg();
	$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
	$gnupg->addencryptkey( $fp );
	$gnupg->addsignkey( $FINGERPRINT, '' );
	$enc = $gnupg->encryptsign( serialize($friends) );
	$fn = 'feeds/' . $putrelids[$fp] . '.asc';
	$fd = fopen( $fn, 'wt' );
	fwrite( $fd, $enc );
	fclose( $fd );
	chmod( $fn, 0644 );
}

header('Location: ' . $IDENTITY );
?>
