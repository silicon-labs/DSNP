<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

requireOwner();

$furi = $_GET['uri'];

$data = read_data();
$friends = $data['friends'];
$getrelids = $data['getrelids'];

$asc = $furi . 'tokens/' . $getrelids[$friends[$furi]] . '.asc';
$response = http_get( $asc, array("timeout"=>1), $info );
$message = http_parse_message( $response );

$gnupg = new gnupg();
$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->adddecryptkey( $FINGERPRINT, "" );
$plain= "";
$res = $gnupg->decryptverify( $message->body, $plain );

header('Location: ' . $furi . 'submitftok.php?token=' . urlencode( $plain ) );
