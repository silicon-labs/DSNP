<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

$furi = $_GET['uri'];

$asc = $furi . 'tokens/' . $FINGERPRINT . '.asc';
$response = http_get( $asc, array("timeout"=>1), $info );
$message = http_parse_message( $response );

$gnupg = new gnupg();
$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->adddecryptkey( $FINGERPRINT, "" );
$plain= "";
$res = $gnupg->decryptverify( $message->body, $plain );

$s = split(' ', $plain);
$relid = $s[0];
$relid_friend = $s[1];

if ( $_SESSION['relid'] == $relid ) {
	echo "friend request submitted<br>\n";
	echo "<a href=\"$IDENTITY\">back to profile</a>";
}
else {
	echo "<center>\n";
	echo "FRIEND REQUEST FAILED<br>\n";
	echo "</center>\n";
}
