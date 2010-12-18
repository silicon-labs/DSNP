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
	define('ROOT', dirname(__FILE__));
}

define('PREFIX', dirname(dirname(dirname(ROOT))));

/**
 * The actual directory name for the "app".
 *
 */
if (!defined('APP_DIR')) {
	define('APP_DIR', 'app' );
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
	define('WEBROOT_DIR', 'webroot');
}

if (!defined('WWW_ROOT')) {
	define('WWW_ROOT', ROOT . DS . APP_DIR . DS . WEBROOT_DIR . DS);
}

/* Location of the data files. */
/* This choose the site to configure for. */
include( PREFIX . '/etc/dsnpua.php' );

define( 'CFG_DB_HOST', $CFG_DB_HOST );
define( 'CFG_DB_USER', $CFG_DB_USER );
define( 'CFG_DB_DATABASE', $CFG_DB_DATABASE );
define( 'CFG_DB_PASS', $CFG_DB_PASS );

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

print CORE_PATH . "\n";

if (!include(CORE_PATH . 'cake' . DS . 'bootstrap.php')) {
	trigger_error("CakePHP core could not be found.  " . 
		"Check the value of CAKE_CORE_INCLUDE_PATH in APP/webroot/index.php.  " .
		"It should point to the directory containing your " . 
		DS . "cake core directory and your " . DS . 
		"vendors root directory.", E_USER_ERROR);
}

exit;

/* Loads configuration params from sites into the Configure class. */
include( ROOT . DS . APP_DIR . '/config/sites.php' );

$Dispatcher = new Dispatcher();
$Dispatcher->dispatch($argv[1]);

//if (Configure::read() > 0) {
//echo "<!-- " . round(getMicrotime() - $TIME_START, 4) . "s -->";
//}
?>
