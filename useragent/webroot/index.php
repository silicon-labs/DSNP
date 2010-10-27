<?php

define( 'DS', DIRECTORY_SEPARATOR );
define( 'ROOT', dirname(dirname(__FILE__)) );
define( 'PREFIX', dirname(dirname(dirname(ROOT))) );

/* Location of the data files. */
/* This choose the site to configure for. */
require( PREFIX . DS . 'etc' . DS . 'config.php' );

define( 'CFG_NAME', $CFG_NAME );
define( 'CFG_URI', $CFG_URI );
define( 'CFG_HOST', $CFG_HOST );
define( 'CFG_PATH', $CFG_PATH );
define( 'CFG_DB_HOST', $CFG_DB_HOST );
define( 'CFG_DB_USER', $CFG_DB_USER );
define( 'CFG_DB_DATABASE', $CFG_DB_DATABASE );
define( 'CFG_ADMIN_PASS', $CFG_ADMIN_PASS );
define( 'CFG_COMM_KEY', $CFG_COMM_KEY );
define( 'CFG_PORT', $CFG_PORT );
define( 'CFG_USE_RECAPTCHA', $CFG_USE_RECAPTCHA );
define( 'CFG_RC_PUBLIC_KEY', $CFG_RC_PUBLIC_KEY );
define( 'CFG_RC_PRIVATE_KEY', $CFG_RC_PRIVATE_KEY );
define( 'CFG_PHOTO_DIR', $CFG_PHOTO_DIR );
define( 'CFG_IM_CONVERT', $CFG_IM_CONVERT );
define( 'CFG_SITE_NAME', $CFG_SITE_NAME );

require( ROOT . DS . 'controller.php' );
require( ROOT . DS . 'database.php' );
require( ROOT . DS . 'route.php' );
require( ROOT . DS . 'dispatch.php' );

exit;

/**
 * The actual directory name for the "app".
 *
 */
if (!defined('APP_DIR')) {
	define('APP_DIR', basename(dirname(dirname(__FILE__))));
}

/**
 * The absolute path to the "cake" directory, WITHOUT a trailing DS.
 *
 */

if (!defined('CAKE_CORE_INCLUDE_PATH')) {
	define('CAKE_CORE_INCLUDE_PATH', ROOT);
}


/**
 * Editing below this line should NOT be necessary.
 * Change at your own risk.
 *
 */

if (!defined('WEBROOT_DIR')) {
	define('WEBROOT_DIR', basename(dirname(__FILE__)));
}

if (!defined('WWW_ROOT')) {
	define('WWW_ROOT', dirname(__FILE__) . DS);
}


define( 'TMP', PREFIX . '/var/lib/dsnp/' . $CFG_NAME . '/tmp/' );
define( 'DATA_DIR', PREFIX . '/var/lib/dsnp/' . $CFG_NAME . '/data' );

if (!defined('CORE_PATH')) {
	if (function_exists('ini_set') && ini_set('include_path', 
			CAKE_CORE_INCLUDE_PATH . PATH_SEPARATOR . ROOT . DS . APP_DIR . 
			DS . PATH_SEPARATOR . ini_get('include_path')))
	{
		define('APP_PATH', null);
		define('CORE_PATH', null);
	} else {
		define('APP_PATH', ROOT . DS . APP_DIR . DS);
		define('CORE_PATH', CAKE_CORE_INCLUDE_PATH . DS);
	}
}

if (!include(CORE_PATH . 'cake' . DS . 'bootstrap.php')) {
	trigger_error("CakePHP core could not be found.  " . 
		"Check the value of CAKE_CORE_INCLUDE_PATH in APP/webroot/index.php.  " .
		"It should point to the directory containing your " . 
		DS . "cake core directory and your " . DS . 
		"vendors root directory.", E_USER_ERROR);
}

/* Loads configuration params from sites into the Configure class. */
include( ROOT . DS . APP_DIR . '/config/sites.php' );

/* If there is a user, but no slash following it, then add one. */
if ( isset( $_GET['url'] ) ) {
	$url = $_GET['url'];
	if ( strlen( $url ) > 0 && preg_match( '/^([^\/]*)\//', $url ) == 0 ) {
		header( "Location: " . Configure::read('CFG_PATH') . "$url/" );
		exit;
	}
}

$Dispatcher = new Dispatcher();
$Dispatcher->dispatch($url);

//if (Configure::read() > 0) {
//echo "<!-- " . round(getMicrotime() - $TIME_START, 4) . "s -->";
//}
?>
