<?php
class Controller
{
	var $controller = null;
	var $method = null;
	var $hasView = true;

	var $CFG_NAME = null;
	var $CFG_URI = null;
	var $CFG_HOST = null;
	var $CFG_PATH = null;
	var $CFG_DB_HOST = null;
	var $CFG_DB_USER = null;
	var $CFG_DB_DATABASE = null;
	var $CFG_ADMIN_PASS = null;
	var $CFG_COMM_KEY = null;
	var $CFG_PORT = null;
	var $CFG_USE_RECAPTCHA = null;
	var $CFG_RC_PUBLIC_KEY = null;
	var $CFG_RC_PRIVATE_KEY = null;
	var $CFG_PHOTO_DIR = null;
	var $CFG_IM_CONVERT = null;
	var $CFG_SITE_NAME = null;

	function Controller()
	{
		# Connect to the database.
		$conn = mysql_connect( CFG_DB_HOST, CFG_DB_USER, CFG_ADMIN_PASS )
			or die ('ERROR: could not connect to database');
		mysql_select_db( CFG_DB_DATABASE ) 
			or die('ERROR: could not select database ' . CFG_DB_DATABASE );

		$this->CFG_URI = CFG_URI;
		$this->CFG_HOST = CFG_HOST;
		$this->CFG_PATH = CFG_PATH;
		$this->CFG_DB_HOST = CFG_DB_HOST;
		$this->CFG_DB_USER = CFG_DB_USER;
		$this->CFG_DB_DATABASE = CFG_DB_DATABASE;
		$this->CFG_ADMIN_PASS = CFG_ADMIN_PASS;
		$this->CFG_COMM_KEY = CFG_COMM_KEY;
		$this->CFG_PORT = CFG_PORT;
		$this->CFG_USE_RECAPTCHA = CFG_USE_RECAPTCHA;
		$this->CFG_RC_PUBLIC_KEY = CFG_RC_PUBLIC_KEY;
		$this->CFG_RC_PRIVATE_KEY = CFG_RC_PRIVATE_KEY;
		$this->CFG_IM_CONVERT = CFG_IM_CONVERT;
	}

	function redirect( $location )
	{
		header("Location: $location");
		$this->hasView = false;
	}
}
?>
