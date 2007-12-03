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
$putrelid = sha1( uniqid( mt_rand() ) );

# Store the fingerprint and relid. 
$data = read_data();
$data['putrelids'][$fp] = $putrelid;
$data['fingerprints'][$furi] = $fp;
write_data( $data );

# Create the put relid message for the identity requesting friendship.
$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->addencryptkey( $fp );
$gnupg->addsignkey( $FINGERPRINT, '' );
$enc = $gnupg->encryptsign( $putrelid );
$fn = 'relid/' . $fp . '.asc';
$fd = fopen( $fn, 'wt' );
fwrite( $fd, $enc );
fclose( $fd );
chmod( $fn, 0644 );

header('Location: ' . $furi . 'returnrelid.php?uri=' . urlencode( $IDENTITY ) );
