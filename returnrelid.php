<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

requireOwner();

$furi = $_GET['uri'];

# Fetch and decrypt the relid from the potential friend.
$asc = $furi . 'getrelid.php?fp=' . $FINGERPRINT;
$response = http_get( $asc, array("timeout"=>1), $info );
$message = http_parse_message( $response );
$gnupg = new gnupg();
$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->adddecryptkey( $FINGERPRINT, "" );
$getrelid = "";
$res = $gnupg->decryptverify( $message->body, $getrelid );

# Create a relationship id for the friend to use.
$putrelid = sha1( uniqid( mt_rand() ) );

# Get the public key of the friend.
$fp = import_id( $gnupg, $furi );

# Store the fingerprint and the relids. 
$data = read_data();
$data['getrelids'][$fp] = $getrelid;
$data['putrelids'][$fp] = $putrelid;
$data['fingerprints'][$furi] = $fp;

# We consider them a friend at this point, though it is only a one-way link. We
# can't prove it.
$data['friends'][$furi] = $fp;

write_data( $data );

# Create the message containing the relid echo and the relid for the friend to
# use.
$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->addencryptkey( $fp );
$gnupg->addsignkey( $FINGERPRINT, '' );
$enc = $gnupg->encryptsign( $getrelid . ' ' . $putrelid );
$fn = 'relid/' . $fp . '.asc';
$fd = fopen( $fn, 'wt' );
fwrite( $fd, $enc );
fclose( $fd );
chmod( $fn, 0644 );

//header( 'Content-type: text/plain' );
//print $enc;
header('Location: ' . $furi . 'submitrelid.php?uri=' . urlencode( $IDENTITY ) );
