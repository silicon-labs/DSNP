<?php
class PublicCredController extends Controller
{
	var $function = array(
		'login' => array(),
		'slogin' => array(
			array( post => 'pass' )
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
		if ( isset( $_REQUEST['d'] ) )	
			$this->set('dest', $_REQUEST['d'] );
	}

	function slogin()
	{
		$pass = $this->args['pass'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->login( $this->USER[USER], $pass );

		if ( !ereg("^OK ([-A-Za-z0-9_]+) ([-A-Za-z0-9_]+) ([0-9]+)",
				$connection->result, $regs) )
		{
			$this->error(
				'Login failed.',
				'Please press the back button to try again.'
			);
		}

		$this->startSession();
		$_SESSION[ROLE] = 'owner';
		$_SESSION[hash] = $regs[1];
		$_SESSION[token] = $regs[2];
	
#		if ( isset( $_POST['d'] ) )
#			$this->redirect( urldecode($_POST['d']) );
#		else
			$this->userRedirect( "/" );
	}

	function sflogin()
	{
		$hash = $this->args[h];

		/* Since this is the the public cred controller, we are not logged in
		 * as anyone. */

#		/* Maybe we are already logged in as this friend. */
#		if ( isset( $this->ROLE ) && $this->ROLE === 'friend' && 
#				isset( $_SESSION['hash'] ) && $_SESSION['hash'] === $hash )
#		{
#			header( "Location: " . Router::url( "/$this->USER_NAME/" ) );
#		}
#		else {

			$connection = new Connection;
			$connection->openLocalPriv();

			$connection->ftokenRequest( $this->USER[USER], $hash );

#			if ( !ereg("^OK ([-A-Za-z0-9_]+) ([-A-Za-z0-9_]+) ([0-9]+)",
#					$connection->result, $regs) )
#			{
#			$send = 
#				"SPP/0.1 " . $this->CFG_URI . "\r\n" . 
#				"comm_key " . $this->CFG_COMM_KEY . "\r\n" .
#				"ftoken_request " . $this->USER_NAME . " $hash\r\n";

			if ( ereg("^OK ([-A-Za-z0-9_]+) ([^ \t\n\r]+) ([-A-Za-z0-9_]+)", 
					$connection->result, $regs) )
			{
				$arg_h = 'h=' . urlencode( $regs[3] );
				$arg_reqid = 'reqid=' . urlencode( $regs[1] );
				$friend_id = $regs[2];
				$dest = "";

				# FIXME: put this into the args definition.
				if ( isset( $_GET['d'] ) )
					$dest = "&d=" . urlencode($_GET['d']);
					
				$this->redirect(
					"{$friend_id}cred/retftok?{$arg_h}&{$arg_reqid}{$dest}" );
			}
			else {
				$this->userRedirect( "/" );
			}
#		}
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
		if ( ereg("^OK ([-A-Za-z0-9_]+) ([0-9a-f]+) ([^ \t\r\n]*)",
				$connection->result, $regs ) )
		{
			$hash = $regs[1];
			$identity = $regs[3];

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

			$BROWSER = dbQuery( "
				SELECT id, user_id, user, friend_id, identity, name
				FROM friend_claim WHERE user_id = %l AND friend_id = %e
				",
				$this->USER[ID],
				$identity
			);

			# FIXME: check result
			$BROWSER = $BROWSER[0];
			$_SESSION[BROWSER] = $BROWSER;
			#$this->Session->write( 'BROWSER', $BROWSER );

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
