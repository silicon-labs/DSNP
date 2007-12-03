<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

requireOwner();

$furi = $_GET['uri'];

$asc = $furi . 'getrelid.php?fp=' . $FINGERPRINT;
$response = http_get( $asc, array("timeout"=>1), $info );
$message = http_parse_message( $response );

$gnupg = new gnupg();
$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->adddecryptkey( $FINGERPRINT, "" );
$plain= "";
$res = $gnupg->decryptverify( $message->body, $plain );

# Create a relationship id for the friend to use.
$relid = sha1( uniqid( mt_rand() ) );
$_SESSION['relid'] = $relid;

# Get the public key.
$fp = import_id( $gnupg, $furi );

$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->addencryptkey( $fp );
$gnupg->addsignkey( $FINGERPRINT, '' );
$enc = $gnupg->encryptsign( $plain . ' ' . $relid );
$fn = 'relid/' . $fp . '.asc';
$fd = fopen( $fn, 'wt' );
fwrite( $fd, $enc );
fclose( $fd );
chmod( $fn, 0644 );

//header( 'Content-type: text/plain' );
//print $enc;
header('Location: ' . $furi . 'submitrelid.php?uri=' . urlencode( $IDENTITY ) );
