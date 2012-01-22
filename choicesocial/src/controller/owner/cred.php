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
				get => 'dsnp_hash',
				type => 'base64', 
				length => HASH_BASE64_SIZE 
			),
			array( 
				get => 'dsnp_reqid',
				type => 'base64', 
				length => TOKEN_BASE64_SIZE
			),
			array(
				get => 'dest',
				optional => true
			)
		),
		'sflogin' => array(
			array( 
				get => 'dsnp_hash',
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
		$hash = $this->args['dsnp_hash'];
		$reqid = $this->args['dsnp_reqid'];

		$connection = new Connection;
		$connection->openLocal();

		/* Remember: if it comes back there was no error. */
		$connection->ftokenResponse( $_SESSION['token'], $hash, $reqid );

		$arg_dsnp   = 'dsnp=submit_ftoken';
		$arg_ftoken = 'dsnp_ftoken=' . urlencode( $connection->ftoken );

		$dest = addArgs( iduriToIdurl( $connection->iduri ), "{$arg_dsnp}&{$arg_ftoken}" );

		if ( isset( $this->args['dest'] ) ) {
			$arg_dest = "dest=" . urlencode( $this->args['dest'] );
			$dest = addArgs( $dest, $arg_dest );
		}

		$this->redirect( $dest );
	}

	function sflogin()
	{
		/* Currently logged in as an owner, and the user is attempting to login
		 * as a friend. Destroy the current session, then initiate the friend
		 * login. */
		$hash = $this->args['dsnp_hash'];
		$this->destroySession();
		$this->submitFriendLogin( $hash );
	}
}
?>
