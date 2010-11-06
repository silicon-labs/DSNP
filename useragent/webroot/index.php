<?php

define( 'DS', DIRECTORY_SEPARATOR );
define( 'ROOT', dirname(dirname(__FILE__)) );
define( 'PREFIX', dirname(dirname(dirname(ROOT))) );

define( 'ACTIVITY_SIZE', 30 );

/* This selects the site to configure for. */
require( PREFIX . DS . 'etc' . DS . 'config.php' );

require( ROOT . DS . 'connection.php' );
require( ROOT . DS . 'controller.php' );
require( ROOT . DS . 'view.php' );
require( ROOT . DS . 'database.php' );
require( ROOT . DS . 'route.php' );
require( ROOT . DS . 'session.php' );
require( ROOT . DS . 'dispatch.php' );

?>
