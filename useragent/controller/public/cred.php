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

		if ( !$connection->success ) {
			$this->userError(
				'Login failed.',
				'Please press the back button to try again.'
			);
		}

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
#		$this->activateSession();
#		# No session yet. Maybe going to set it up.

		$ftoken = $this->args['ftoken'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->submitFtoken( $ftoken );

		/* FIXME: If there is no friend claim ... send back a reqid anyways.
		 * Don't want to give away that there is no claim, otherwise it would
		 * be possible to probe  Would be good to fake this with an appropriate
		 * time delay. */

		/* Remmber that if we return from the above then we have success. */
		$hash = $connection->regs[1];
		$iduri = $connection->regs[3];

#		# Login successful.
#		$this->Session->write( 'ROLE', 'friend' );
#		$this->Session->write( 'NETWORK_NAME', '-' );
#		$this->Session->write( 'token', $ftoken );
#		$this->Session->write( 'hash', $hash );
		
		$this->startSession();
		$_SESSION['ROLE'] = 'friend';
		$_SESSION['NETWORK_NAME'] = '-';
		$_SESSION['hash'] = $hash;
		$_SESSION['token'] = $ftoken;

#		$friendClaim = dbQuery( "
#			SELECT friend_claim.id AS id, identity.iduri AS iduri
#			FROM friend_claim 
#			JOIN identity on friend_claim.identity_id = identity.id
#			WHERE user_id = %l AND iduri = %e
#			",
#			$this->USER[ID],
#			$identity
#		);

		# FIXME: check result
		#$BROWSER['ID'] = $friendClaim[0]['id'];
		$BROWSER['iduri'] = $identity;

		$_SESSION['BROWSER'] = $BROWSER;

		/* FIXME: check for dest (d). */
		#if ( isset( $_GET['d'] ) )
		#	$this->redirect( $_GET['d'] );
		#else

		$this->userRedirect( '/' );
	}
}
