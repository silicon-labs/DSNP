<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

$furi = $_GET['uri'];

# Fetch and decrypt the get and put relids.
$asc = $furi . 'getrelid.php?fp=' . $FINGERPRINT;
$response = http_get( $asc, array("timeout"=>1), $info );
$message = http_parse_message( $response );
$gnupg = new gnupg();
$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->adddecryptkey( $FINGERPRINT, "" );
$relids = "";
$res = $gnupg->decryptverify( $message->body, $relids );

# Get individual relids.
$s = split(' ', $relids);
$putrelid = $s[0];
$getrelid = $s[1];

# Store getrelid.
$data = read_data();
$fp = $data['fingerprints'][$furi];
$data['getrelids'][$fp] = $getrelid;
write_data( $data );

if ( $putrelid == $data['putrelids'][$fp] ) {
	echo "friend request submitted<br>\n";
	echo "<a href=\"$IDENTITY\">back to profile</a>";
}
else {
	echo "<center>\n";
	echo "FRIEND REQUEST FAILED<br>\n";
	echo "</center>\n";
}
