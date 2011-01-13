<?php

require( ROOT . DS . 'controller/cred.php' );

class OwnerCredController extends CredController
{
	var $function = array(
		'login' => array(
			array( 
				get => 'd',
				optional => true
			),
		),
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
		if ( isset( $this->args['d'] ) )	
			$this->vars['dest'] = $this->args['d'];
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
		$connection->openLocal();

		$connection->ftokenResponse( $this->USER[USER], $hash, $reqid );

		/* Remember: if it comes back there was no error. */
		$arg_ftoken = 'ftoken=' . urlencode( $connection->ftoken );
		$dest = "";
		if ( isset( $_GET['d'] ) )
			$dest = "&d=" . urlencode($_GET['d']);
		$this->redirect("{$connection->iduri}cred/sftoken?{$arg_ftoken}{$dest}" );
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
