<?php

define( 'EC_PEER_FAILED_SSL',         100 );
define( 'EC_FRIEND_REQUEST_EXISTS',   101 );

function userError( $code, $args )
{
	print '<html xmlns="http://www.w3.org/1999/xhtml">';
	print '<head>';
	print '<title>OOPS</title>';
	print '</head>';
	print '<body>';
	print '<p>';
	print '<h1> Ooops, there was an error!</h1><big><div style="width: 50%">';
	include( ROOT . DS . 'errtype.php' );
	print '</div></big>';
	print '</body>';
	print '</html>';

	exit;
}

?>
