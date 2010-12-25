<?php

define( 'EC_SSL_PEER_FAILED_VERIFY',  100 );
define( 'EC_FRIEND_REQUEST_EXISTS',   101 );
define( 'EC_DSNPD_NO_RESPONSE',       102 );
define( 'EC_DSNPD_TIMEOUT',           103 );
define( 'EC_SOCKET_CONNECT_FAILED',   104 );
define( 'EC_SSL_CONNECT_FAILED',      105 );
define( 'EC_SSL_WRONG_HOST',             106 );
define( 'EC_SSL_CA_CERT_LOAD_FAILURE',   107 );

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
