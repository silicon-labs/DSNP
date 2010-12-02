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
		$hash = $this->args[h];
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

		# If there is a result then the login is successful. 
		if ( $connection->success ) {
			$hash = $connection->regs[1];
			$identity = $connection->regs[3];

#			# Login successful.
#			$this->Session->write( 'ROLE', 'friend' );
#			$this->Session->write( 'NETWORK_NAME', '-' );
#			$this->Session->write( 'token', $ftoken );
#			$this->Session->write( 'hash', $hash );
		
			$this->startSession();
			$_SESSION[ROLE] = 'friend';
			$_SESSION[NETWORK_NAME] = '-';
			$_SESSION[hash] = $hash;
			$_SESSION[token] = $ftoken;

			$friendClaim = dbQuery( "
				SELECT id, user_id, user, friend_id, name
				FROM friend_claim WHERE user_id = %l AND friend_id = %e
				",
				$this->USER[ID],
				$identity
			);

			# FIXME: check result
			$BROWSER[ID] = $friendClaim[0]['id'];
			$BROWSER[URI] = $friendClaim[0]['friend_id'];

			$_SESSION[BROWSER] = $BROWSER;

#			if ( isset( $_GET['d'] ) )
#				$this->redirect( $_GET['d'] );
#			else
				$this->userRedirect( '/' );
		}
		else {
			echo "<center>\n";
			echo "FRIEND LOGIN FAILED<br> $res\n";
			echo "</center>\n";
			exit;
		}
	}
}
