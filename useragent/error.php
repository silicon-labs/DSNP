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
	include( ROOT . DS . 'errtype.php' );
	print '</body>';
	print '</html>';
}

?>
