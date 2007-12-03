<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

$furi = $_POST['uri'];

$data = read_data( );

$gnupg = new gnupg();

# Get the public key.
$fp = import_id( $gnupg, $furi );

# Create a relationship id for the friend to use.
$relid = sha1( uniqid( mt_rand() ) );
$_SESSION['relid'] = $relid;

$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->addencryptkey( $fp );
$gnupg->addsignkey( $FINGERPRINT, '' );
$enc = $gnupg->encryptsign( $relid );
$fn = 'tokens/' . $fp . '.asc';
$fd = fopen( $fn, 'wt' );
fwrite( $fd, $enc );
fclose( $fd );
chmod( $fn, 0644 );

header('Location: ' . $furi . 'returnrelid.php?uri=' . urlencode( $IDENTITY ) );
