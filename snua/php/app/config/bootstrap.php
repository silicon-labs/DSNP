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
 * @subpackage    cake.app.config
 * @since         CakePHP(tm) v 0.10.8.2117
 * @version       $Revision$
 * @modifiedby    $LastChangedBy$
 * @lastmodified  $Date$
 * @license       http://www.opensource.org/licenses/mit-license.php The MIT License
 */

/**
 *
 * This file is loaded automatically by the app/webroot/index.php file after the core bootstrap.php is loaded
 * This is an application wide file to load any function that is not used within a class define.
 * You can also use this to include or require any files in your application.
 *
 */

/**
 * The settings below can be used to set additional paths to models, views and controllers.
 * This is related to Ticket #470 (https://trac.cakephp.org/ticket/470)
 *
 * $modelPaths = array('full path to models', 'second full path to models', 'etc...');
 * $viewPaths = array('this path to views', 'second full path to views', 'etc...');
 * $controllerPaths = array('this path to controllers', 'second full path to controllers', 'etc...');
 *
 */


include( 'config.php' );

if ( !isset( $CFG_URI ) )
	die("config.php: could not select installation\n");

if ( get_magic_quotes_gpc() )
	die("the SPP software assumes PHP magic quotes to be off\n");

Configure::write( 'CFG_URI', $CFG_URI );
Configure::write( 'CFG_HOST', $CFG_HOST );
Configure::write( 'CFG_PATH', $CFG_PATH );
Configure::write( 'CFG_DB_HOST', $CFG_DB_HOST );
Configure::write( 'CFG_DB_USER', $CFG_DB_USER );
Configure::write( 'CFG_DB_DATABASE', $CFG_DB_DATABASE );
Configure::write( 'CFG_ADMIN_PASS', $CFG_ADMIN_PASS );
Configure::write( 'CFG_COMM_KEY', $CFG_COMM_KEY );
Configure::write( 'CFG_PORT', $CFG_PORT );
Configure::write( 'CFG_USE_RECAPTCHA', $CFG_USE_RECAPTCHA );
Configure::write( 'CFG_RC_PUBLIC_KEY', $CFG_RC_PUBLIC_KEY );
Configure::write( 'CFG_RC_PRIVATE_KEY', $CFG_RC_PRIVATE_KEY );
Configure::write( 'CFG_PHOTO_DIR', $CFG_PHOTO_DIR );
Configure::write( 'CFG_IM_CONVERT', $CFG_IM_CONVERT );
Configure::write( 'CFG_SITE_NAME', $CFG_SITE_NAME );

?>
