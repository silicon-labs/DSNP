<?php
/* SVN FILE: $Id$ */
/**
 * Short description for file.
 *
 * Long description for file
 *
 * PHP versions 4 and 5
 *
 * CakePHP(tm) :  Rapid Development Framework (http://www.cakephp.org)
 * Copyright 2005-2008, Cake Software Foundation, Inc. (http://www.cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @filesource
 * @copyright     Copyright 2005-2008, Cake Software Foundation, Inc. (http://www.cakefoundation.org)
 * @link          http://www.cakefoundation.org/projects/info/cakephp CakePHP(tm) Project
 * @package       cake
 * @subpackage    cake.app.webroot
 * @since         CakePHP(tm) v 0.2.9
 * @version       $Revision$
 * @modifiedby    $LastChangedBy$
 * @lastmodified  $Date$
 * @license       http://www.opensource.org/licenses/mit-license.php The MIT License
 */
/**
 * Use the DS to separate the directories in other defines
 */

if (!defined('DS')) {
	define('DS', DIRECTORY_SEPARATOR);
}

/**
 * These defines should only be edited if you have cake installed in
 * a directory layout other than the way it is distributed.
 * When using custom settings be sure to use the DS and do not add a trailing DS.
 */

/**
 * The full path to the directory which holds "app", WITHOUT a trailing DS.
 *
 */
if (!defined('ROOT')) {
	define('ROOT', dirname(dirname(dirname(__FILE__))));
}

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

include( "config.php" );

if ( !$CFG_URI )
	die("config.php: could not select installation\n");

if ( get_magic_quotes_gpc() )
	die("the SPP software assumes PHP magic quotes to be off\n");

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


if (isset($_GET['url']) && ( $_GET['url'] === 'favicon.ico' || $_GET['url'] === 'robots.txt' ) )
	return;
else {
	if ( isset( $_GET['url'] ) ) {
		$url = $_GET['url'];
		if ( preg_match( '/^[^\/]+\//', $url ) ) {
			$u = preg_replace( '/([^\/]+).*/', '\1', $url );

			if ( $u === 'admin' ) {
				# Do nothing here. Use the admin controller. 
			}
			else {
				$url = preg_replace( '/^[^\/]+\//', 'user/', $url );

				$USER_NAME = $u;
				$USER_PATH = "${CFG_PATH}$USER_NAME/";
				$USER_URI = "${CFG_URI}$USER_NAME/";

				define( 'USER_NAME', $USER_NAME );
				define( 'USER_PATH', $USER_PATH );
				define( 'USER_URI', $USER_URI );

				if ( $url == null || strlen( $url ) == 0 )
					$url = "user";
			}
		}
	}

	$Dispatcher = new Dispatcher();
	$Dispatcher->dispatch($url);
}
if (Configure::read() > 0) {
	echo "<!-- " . round(getMicrotime() - $TIME_START, 4) . "s -->";
}
?>
