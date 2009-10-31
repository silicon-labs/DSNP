<?php

class CredController extends AppController
{
	var $name = 'Cred';
	var $uses = array();

	function beforeFilter()
	{
		$this->checkUser();
		$this->maybeActivateSession();
	}

	function index()
	{
		$this->render( 'login' );
	}

	function login()
	{
	}

	function slogin()
	{
		$this->activateSession();

		$pass = $_POST['pass'];

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"login $this->USER_NAME $pass\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK ([-A-Za-z0-9_]+) ([-A-Za-z0-9_]+) ([0-9]+)", $res, $regs) ) {
			include('lib/loginfailed.php');
		}
		else {
			# Login successful.
			$this->Session->write( 'auth', 'owner' );
			$this->Session->write( 'hash', $regs[1] );
			$this->Session->write( 'token', $regs[2] );

			$this->redirect( "/$this->USER_NAME/" );
		}
	}

	function sflogin()
	{
		$hash = $_REQUEST['h'];

		if ( !$hash )
			die('no hash given');

		/* Maybe we are already logged in as this friend. */
		if ( isset( $_SESSION['auth'] ) && $_SESSION['auth'] == 'friend' && 
				isset( $_SESSION['hash'] ) && $_SESSION['hash'] == $hash ) {
			header( "Location: $this->USER_PATH" );
		}
		else {
			/* Not logged in as the hashed user. */
			$fp = fsockopen( 'localhost', $this->CFG_PORT );
			if ( !$fp )
				exit(1);

			$send = 
				"SPP/0.1 " . CFG_URI . "\r\n" . 
				"comm_key " . CFG_COMM_KEY . "\r\n" .
				"ftoken_request " . USER_NAME . " $hash\r\n";
			fwrite($fp, $send);

			$res = fgets($fp);

			if ( ereg("^OK ([-A-Za-z0-9_]+) ([^ \t\n\r]+) ([-A-Za-z0-9_]+)", $res, $regs) ) {
				$arg_h = 'h=' . urlencode( $regs[3] );
				$arg_reqid = 'reqid=' . urlencode( $regs[1] );
				$friend_id = $regs[2];
				$dest = "";
				if ( isset( $_GET['d'] ) )
					$dest = "&d=" . urlencode($_GET['d']);
					
				header( "Location: ${friend_id}retftok?${arg_h}&${arg_reqid}" . $dest );
			}
		}
	}
	
	function retftok()
	{
		$this->requireOwner();

		$hash = $_REQUEST['h'];
		$reqid = $_GET['reqid'];

		if ( !$hash )
			die('no hash given');

		if ( !$reqid )
			die('no reqid given');

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"ftoken_response " . $this->USER_NAME . " $hash $reqid\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);

		if ( ereg("^OK ([-A-Za-z0-9_]+) ([^ \t\r\n]*)", $res, $regs) ) {
			$arg_ftoken = 'ftoken=' . urlencode( $regs[1] );
			$friend_id = $regs[2];
			$dest = "";
			if ( isset( $_GET['d'] ) )
				$dest = "&d=" . urlencode($_GET['d']);
			header("Location: ${friend_id}sftoken?${arg_ftoken}" . $dest );
		}
		else {
			echo $res;
		}
	}
	
	function sftoken()
	{
		$this->activateSession();

		# No session yet. Maybe going to set it up.

		$ftoken = $_GET['ftoken'];

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"submit_ftoken $ftoken\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);

		# If there is a result then the login is successful. 
		if ( ereg("^OK ([-A-Za-z0-9_]+) ([0-9a-f]+) ([^ \t\r\n]*)", $res, $regs) ) {
			# Login successful.
			$this->Session->write( 'auth', 'friend' );
			$this->Session->write( 'token', $ftoken );
			$this->Session->write( 'hash', $regs[1] );
			$this->Session->write( 'identity', $regs[3] );

			if ( isset( $_GET['d'] ) )
				$this->redirect( $_GET['d'] );
			else
				$this->redirect( "/" . $this->USER_NAME . "/" );
		}
		else {
			echo "<center>\n";
			echo "FRIEND LOGIN FAILED<br>\n";
			echo "</center>\n";
		}
	}

	function logout()
	{
		$this->Session->destroy();
		$this->redirect( "/" . $this->USER_NAME . "/" );
	}
}
?>
