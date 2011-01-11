<?php

define( 'EC_SSL_PEER_FAILED_VERIFY',        100 );
define( 'EC_FRIEND_REQUEST_EXISTS',         101 );
define( 'EC_DSNPD_NO_RESPONSE',             102 );
define( 'EC_DSNPD_TIMEOUT',                 103 );
define( 'EC_SOCKET_CONNECT_FAILED',         104 );
define( 'EC_SSL_CONNECT_FAILED',            105 );
define( 'EC_SSL_WRONG_HOST',                106 );
define( 'EC_SSL_CA_CERT_LOAD_FAILURE',      107 );
define( 'EC_FRIEND_CLAIM_EXISTS',           108 );
define( 'EC_CANNOT_FRIEND_SELF',            109 );
define( 'EC_USER_NOT_FOUND',                110 );
define( 'EC_INVALID_ROUTE',                 111 );
define( 'EC_USER_EXISTS',                   112 );
define( 'EC_RSA_KEY_GEN_FAILED',            113 );
define( 'EC_INVALID_LOGIN',                 114 );
define( 'EC_DATABASE_ERROR',                115 );
define( 'EC_INVALID_USER',                  116 );
define( 'EC_READ_ERROR',                    117 );
define( 'EC_PARSE_ERROR',                   118 );
define( 'EC_RESPONSE_IS_ERROR',             119 );
define( 'EC_SSL_NEW_CONTEXT_FAILURE',       120 );
define( 'EC_SSL_CA_CERTS_NOT_SET',          121 );
define( 'EC_FRIEND_REQUEST_INVALID',        122 );
define( 'EC_IDENTITY_ID_INVALID',           123 );
define( 'EC_USER_ID_INVALID',               124 );
define( 'EC_STOPPING',                      125 );
define( 'EC_NOT_PREFRIEND',                 126 );
define( 'EC_DECRYPT_VERIFY_FAILED',         127 );
define( 'EC_NO_PRIMARY_NETWORK',            128 );
define( 'EC_FRIEND_CLAIM_NOT_FOUND',        129 );
define( 'EC_PUT_KEY_FETCH_ERROR',           130 );
define( 'EC_INVALID_RELID',                 131 );
define( 'EC_IDENTITY_HASH_INVALID',         132 );
define( 'EC_INVALID_FTOKEN',                133 );
define( 'EC_INVALID_FTOKEN_REQUEST',        134 );
define( 'EC_FLOGIN_TOKEN_WRONG_SIZE',       135 );
define( 'EC_BROADCAST_RECIPIENT_INVALID',   136 );
define( 'EC_REQUEST_ID_INVALID',			137 );
define( 'EC_LOGIN_TOKEN_INVALID',           138 );
define( 'EC_TOKEN_WRONG_SIZE',              139 );
define( 'EC_NOT_IMPLEMENTED',				140 );

function userError( $code, $args )
{
	print '<html xmlns="http://www.w3.org/1999/xhtml">';
	print '<head>';
	print '<title>OOPS</title>';
	print '</head>';
	print '<body>';
	print '<p>';
	print '<h1> Ooops, there was an error!</h1><big><div style="width: 50%">';
	include( ROOT . '/error.php' );
	print '</div></big>';
	print '</body>';
	print '</html>';

	exit;
}

?>
