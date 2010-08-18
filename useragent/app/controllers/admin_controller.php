<?php

class AdminController extends AppController
{
	var $name = 'Admin';

    // var $uses = null; works too
    var $uses = null;

	function index()
	{
		# Load the user's sent friend requests
		$users = dbQuery( "SELECT * from user" );
		$this->set( 'users', $users );
	}

	function newuser()
	{

	}

	function snewuser()
	{
		$user = $this->data['User']['user'];
		$pass1 = $this->data['User']['pass1'];
		$pass2 = $this->data['User']['pass2'];

		if ( $pass1 != $pass2 )
			die("password mismatch");

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"new_user $user $pass1\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK", $res) )
			die( "FAILURE *** New user creation failed with: <br> $res" );
   	
		$identity = $this->CFG_URI . $user . '/';
		dbQuery( "UPDATE user SET name = %e, identity = %e, type = %l WHERE user = %e ",
			$user, $identity, 0, $user );

		# Create the photo directory.
		$photoDirCmd =  "umask 0002; mkdir " . DATA_DIR . "/$user";
		system( $photoDirCmd );

		$this->redirect( "/" );
	}
}
