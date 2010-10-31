<?php
class Connection
{
	var $fp;
	var $result;

	function openLocal()
	{
		global $CFG;

		$this->fp = fsockopen( 'localhost', $CFG[PORT] );
		if ( ! $this->fp )
			exit(1);
		
		$send = 
			"SPP/0.1 " . $CFG[URI] . "\r\n" .
			"comm_key " . $CFG[COMM_KEY] . "\r\n";
		fwrite( $this->fp, $send );
	}

	function openLocalPriv()
	{
		global $CFG;
		$this->openLocal();
		$send = "comm_key " . $CFG[COMM_KEY] . "\r\n";
		fwrite( $this->fp, $send );
	}

	function command( $cmd )
	{
		fwrite( $this->fp, $cmd );
		$this->result = fgets( $this->fp );
	}

	function checkResult( $pat )
	{
		if ( !ereg( $pat , $this->result ) ) {
			die( "FAILURE *** New user creation failed with: <br> " .
					$this->result );
		}
	}
};

class Controller
{
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

	function siteRedirect( $location )
	{
		global $CFG;
		global $USER;
		header("Location: {$this->CFG[PATH]}$location");
		$this->hasView = false;
	}
	function userRedirect( $location )
	{
		global $CFG;
		global $USER;
		header("Location: {$this->CFG[PATH]}/{$this->USER[USER]}$location");
		$this->hasView = false;
	}

	function error( $short, $details )
	{
		print $short . "<br>" . $details;
		exit;
	}
}
?>
