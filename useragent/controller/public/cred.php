<?php

require( ROOT . DS . 'controller/cred.php' );

class PublicCredController extends CredController
{
	var $function = array(
		'login' => array(
			array( 
				get => 'd',
				optional => true
			),
		),
		'slogin' => array(
			array( post => 'pass' ),
			array( 
				post => 'd',
				optional => true
			),
		),
		'sflogin' => array(
			array( 
				get => 'h',
				type => 'base64', 
				length => HASH_BASE64_SIZE 
			)
		),
		'sftoken' => array(
			array( 
				get => 'ftoken',
				type => 'base64', 
				length => TOKEN_BASE64_SIZE 
			)
		),
	);

	function login()
	{
		if ( isset( $this->args['d'] ) )	
			$this->vars['dest'] = $this->args['d'];
	}

	function slogin()
	{
		$pass = $this->args['pass'];
		$dest = $this->args['d'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->login( $this->USER[USER], $pass );

		$this->startSession();
		$_SESSION[ROLE] = 'owner';
		$_SESSION[hash] = $connection->regs[1];
		$_SESSION[token] = $connection->regs[2];
	
		if ( isset( $dest ) ) 
			$this->redirect( $dest );
		else
			$this->userRedirect( "/" );
	}

	function sflogin()
	{
		/* Initiate the friend login process. */
		$hash = $this->args['h'];
		$this->submitFriendLogin( $hash );
	}

	function sftoken()
	{
		$ftoken = $this->args['ftoken'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->submitFtoken( $ftoken );

		$identity = dbQuery( 
			"SELECT id " .
			"FROM identity " .
			"WHERE iduri = %e ",
			$connection->iduri );

		$identityId = $identity[0]['id'];
		$relationship = dbQuery( 
			"SELECT name " .
			"FROM relationship " .
			"WHERE user_id = %L AND identity_id = %L ",
			$this->USER['USER_ID'], $identityId );

		# FIXME: check result
		#$BROWSER['ID'] = $friendClaim[0]['id'];
		$BROWSER['iduri'] = $connection->iduri;
		$BROWSER['name'] = $relationship[0]['name'];

		/* Remmber that if we return from the above then we have success. */
		$this->startSession();
		$_SESSION['ROLE'] = 'friend';
		$_SESSION['hash'] = $connection->hash;
		$_SESSION['token'] = $connection->ftoken;
		$_SESSION['BROWSER'] = $BROWSER;

		/* FIXME: check for dest (d). */
		#if ( isset( $_GET['d'] ) )
		#	$this->redirect( $_GET['d'] );
		#else

		$this->userRedirect( '/' );
	}
}
