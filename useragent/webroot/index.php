<?php

define( 'DS', DIRECTORY_SEPARATOR );
define( 'ROOT', dirname(dirname(__FILE__)) );
define( 'PREFIX', dirname(dirname(dirname(ROOT))) );

define( 'ACTIVITY_SIZE', 30 );
define( 'HASH_BASE64_SIZE', 27 );
define( 'TOKEN_BASE64_SIZE', 22 );

/* This selects the site to configure for. */
require( PREFIX . DS . 'etc' . DS . 'dsnpua.php' );

if ( !isset( $CFG['NAME']  ) )
	die("site not configured properly");


define( 'RECAPTCHA_LIB', ROOT . DS . 'recaptcha-php-1.11' . DS . 'recaptchalib.php' );
define( 'RECAPTCHA_ARGS_OPTIONAL', ! $CFG['USE_RECAPTCHA'] );

require( ROOT . DS . 'connection.php' );
require( ROOT . DS . 'controller.php' );
require( ROOT . DS . 'message.php' );
require( ROOT . DS . 'view.php' );
require( ROOT . DS . 'database.php' );
require( ROOT . DS . 'route.php' );
require( ROOT . DS . 'session.php' );
require( ROOT . DS . 'dispatch.php' );

?>
