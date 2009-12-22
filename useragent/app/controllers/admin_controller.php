<?php

class AdminController extends AppController
{
	var $name = 'Admin';

    // var $uses = null; works too
    var $uses = null;

	function index()
	{
		# Load the user's sent friend requests
		$this->loadModel('User');
		$users = $this->User->find('all');
		$this->set( 'users', $users );
	}

	function newuser()
	{

	}

	function snewuser()
	{
		$user = $this->data['user'];
		$pass1 = $this->data['pass1'];
		$pass2 = $this->data['pass2'];

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
   	
		$this->loadModel('User');
		$this->User->save( array( 
				'user' => $user,
				'name' => $user,
				'identity' => $this->CFG_URI . $user . '/',
				'type' => 0
		));
		$userId = $this->User->id;

		$photoDirCmd =  "umask 0002; mkdir " . DATA_DIR . "/$user";
		system( $photoDirCmd );

		$this->loadModel('FriendGroup');
		$this->FriendGroup->save( array( 
				'user_id' => $userId,
				'name' => 'social'
		));

		$this->redirect( "/" );
	}
}
