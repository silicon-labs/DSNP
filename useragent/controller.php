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

	function Controller()
	{
		global $CFG;

		# Connect to the database.
		$conn = mysql_connect( $CFG[DB_HOST], $CFG[DB_USER], $CFG[ADMIN_PASS] )
			or die ('ERROR: could not connect to database');
		mysql_select_db( $CFG[DB_DATABASE] ) 
			or die('ERROR: could not select database ' . $CFG[DB_DATABASE] );

		$this->CFG = $CFG;
	}

	function redirect( $location )
	{
		header("Location: $location");
		$this->hasView = false;
	}
}
?>
