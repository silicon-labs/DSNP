<?php
class CredController extends Controller
{
	function login()
	{
		if ( isset( $_REQUEST['d'] ) )	
			$this->set('dest', $_REQUEST['d'] );
	}

	function slogin()
	{
		$pass = $_POST['pass'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->command( 
			"login {$this->USER[USER]} $pass\r\n" );

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

	function logout()
	{
		session_destroy();
		setcookie("PHPSESSID", "", time() - 3600, "/");
		$this->userRedirect('/');
	}
}
