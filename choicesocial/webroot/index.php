<?php

define( 'DS', DIRECTORY_SEPARATOR );
define( 'ROOT', dirname(dirname(__FILE__)) );
define( 'PREFIX', dirname(dirname(dirname(ROOT))) );

require( ROOT . '/schema.php' );
require( ROOT . '/definitions.php' );

# This selects the site to configure for.
require( PREFIX . '/etc/choicesocial.php' );
require( ROOT . '/selectconf.php' );

define( 'RECAPTCHA_LIB', ROOT . '/recaptcha-php-1.11/recaptchalib.php' );
define( 'RECAPTCHA_ARGS_OPTIONAL', ! $CFG['USE_RECAPTCHA'] );

require( ROOT . '/usererr.php' );
require( ROOT . '/connection.php' );
require( ROOT . '/controller.php' );
require( ROOT . '/message.php' );
require( ROOT . '/view.php' );
require( ROOT . '/database.php' );
require( ROOT . '/route.php' );
require( ROOT . '/session.php' );
require( ROOT . '/dispatch.php' );

?>
