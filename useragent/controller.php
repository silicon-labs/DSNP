<?php
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
