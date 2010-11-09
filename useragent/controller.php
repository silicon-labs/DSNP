<?php
class Controller
{
	/* Args cleaned according to the function definition. */
	var $args = null;
	var $controller = null;
	var $method = null;
	var $hasView = true;
	var $CFG = null;
	var $USER_NAME = null;

	/* Filled by controllers, made avaialable in views. Each var is defined. */
	var $vars = array();

	function Controller()
	{
		global $CFG;
		global $USER;

		$this->CFG = $CFG;
		$this->USER = $USER;
	}

	function userRedirect( $location )
	{
		global $CFG;
		global $USER;
		header( "Location: {$this->CFG[PATH]}/{$this->USER[USER]}$location" );
		$this->hasView = false;
	}

	function siteRedirect( $location )
	{
		global $CFG;
		global $USER;
		header( "Location: {$this->CFG[PATH]}$location" );
		$this->hasView = false;
	}

	function redirect( $location )
	{
		header( "Location: $location" );
		$this->hasView = false;
	}

	function error( $short, $details )
	{
		print $short . "<br>" . $details;
		exit;
	}

	function startSession()
	{
		setCookieParams();
		if ( !session_start() )
			die("ERROR: could not start a session\n");
	}
}
?>
