<?php
class Controller
{
	var $controller;
	var $method;

	function Controller()
	{
		# Connect to the database.
		$conn = mysql_connect( CFG_DB_HOST, CFG_DB_USER, CFG_ADMIN_PASS )
			or die ('ERROR: could not connect to database');
		mysql_select_db( CFG_DB_DATABASE ) 
			or die('ERROR: could not select database ' . CFG_DB_DATABASE );
	}
}
?>
