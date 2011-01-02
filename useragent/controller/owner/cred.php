<?php

require( ROOT . DS . 'controller/cred.php' );

class OwnerCredController extends CredController
{
	var $function = array(
		'login' => array(),
		'logout' => array(),
		'retftok' => array(
			array( 
				get => 'h',
				type => 'base64', 
				length => HASH_BASE64_SIZE 
			),
			array( 
				get => 'reqid',
				type => 'base64', 
				length => TOKEN_BASE64_SIZE
			)
		),
		'sflogin' => array(
			array( 
				get => 'h',
				type => 'base64', 
				length => HASH_BASE64_SIZE 
			)
		),
	);

	function login()
	{
		/* Login when already logged in. Most likely because user went back. */
		$this->userRedirect( '/' );
	}

	function logout()
	{
		$this->destroySession();
		$this->userRedirect('/');
	}

	function retftok()
	{
		$hash = $this->args['h'];
		$reqid = $this->args['reqid'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->ftokenResponse( $this->USER[USER], $hash, $reqid );

		/* Remember: if it comes back there was no error. */
		$arg_ftoken = 'ftoken=' . urlencode( $connection->regs[1] );
		$iduri = $connection->regs[2];
		$dest = "";
		if ( isset( $_GET['d'] ) )
			$dest = "&d=" . urlencode($_GET['d']);
		$this->redirect("{$iduri}cred/sftoken?{$arg_ftoken}{$dest}" );
	}

	function sflogin()
	{
		/* Currently logged in as an owner, and the user is attempting to login
		 * as a friend. Destroy the current session, then initiate the friend
		 * login. */
		$hash = $this->args[h];
		$this->destroySession();
		$this->submitFriendLogin( $hash );
	}
}
?>
