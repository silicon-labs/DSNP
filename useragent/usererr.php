<?php

define( 'EC_SSL_PEER_FAILED_VERIFY',     100 );
define( 'EC_FRIEND_REQUEST_EXISTS',      101 );
define( 'EC_DSNPD_NO_RESPONSE',          102 );
define( 'EC_DSNPD_TIMEOUT',              103 );
define( 'EC_SOCKET_CONNECT_FAILED',      104 );
define( 'EC_SSL_CONNECT_FAILED',         105 );
define( 'EC_SSL_WRONG_HOST',             106 );
define( 'EC_SSL_CA_CERT_LOAD_FAILURE',   107 );
define( 'EC_FRIEND_CLAIM_EXISTS',        108 );
define( 'EC_CANNOT_FRIEND_SELF',         109 );
define( 'EC_USER_NOT_FOUND',             110 );
define( 'EC_INVALID_ROUTE',              111 );
define( 'EC_USER_EXISTS',                112 );
define( 'EC_RSA_KEY_GEN_FAILED',         113 );
define( 'EC_INVALID_LOGIN',              114 );

function userError( $code, $args )
{
	print '<html xmlns="http://www.w3.org/1999/xhtml">';
	print '<head>';
	print '<title>OOPS</title>';
	print '</head>';
	print '<body>';
	print '<p>';
	print '<h1> Ooops, there was an error!</h1><big><div style="width: 50%">';
	include( ROOT . DS . 'error.php' );
	print '</div></big>';
	print '</body>';
	print '</html>';

	exit;
}

?>
