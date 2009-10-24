<?php

class UserController extends AppController
{
	var $name = 'User';

	function activateSession()
	{
		global $USER_NAME;
		$this->Session->activate( '/spp/' . $USER_NAME . '/' );
	}

	function maybeActivateSession()
	{
		# Only resume sessions or start a new one when *a* session variable is provided
		# Note that it might not be the right one.
		if ( isset( $_COOKIE['CAKEPHP'] ) ) {
			$this->activateSession();
		}
	}

	function beforeFilter()
	{
		$this->maybeActivateSession();
	}

	function setUser()
	{
		global $USER_NAME;
		$user = $this->User->find( 'first', 
				array('conditions' => array('user' => $USER_NAME)));

		if ( $user == null )
			$this->cakeError("userNotFound", array('user' => $USER_NAME));

		$this->set( 'user', $user );
	}

	function indexUser()
	{
		$this->set( 'auth', 'owner' );
		$this->setUser();

		$this->loadModel('Image');
		$images = $this->Image->find('all');
		$this->set('images', $images);
	}

	function indexFriend()
	{
		$this->set( 'auth', 'friend' );
		$this->setUser();
	}

	function indexPublic()
	{
		$this->setUser();
	}

	function index()
	{
		$this->set( 'auth', 'public' );
		if ( $this->Session->valid() ) {
			if ( $this->Session->read('auth') === 'owner' )
				$this->indexUser();
			else if ( $this->Session->read('auth') === 'friend' )
				$this->indexFriend();
			else
				$this->indexPublic();
		}
		else
			$this->indexPublic();
	}

	function login()
	{
	}

	function slogin()  {
		$this->activateSession();

		global $CFG_PORT;
		global $CFG_URI;
		global $CFG_COMM_KEY;
		global $USER_NAME;
		global $USER_PATH;

		$pass = $_POST['pass'];

		$fp = fsockopen( 'localhost', $CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $CFG_URI\r\n" . 
			"comm_key $CFG_COMM_KEY\r\n" .
			"login $USER_NAME $pass\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		#echo $res;
		#exit;
		if ( !ereg("^OK ([-A-Za-z0-9_]+) ([-A-Za-z0-9_]+) ([0-9]+)", $res, $regs) ) {
			include('lib/loginfailed.php');
		}
		else {
			# Login successful.
			$this->Session->write( 'auth', 'owner' );
			$this->Session->write( 'hash', $regs[1] );
			$this->Session->write( 'token', $regs[2] );

			$this->redirect( "/$USER_NAME/" );
		}
	}
}

?>
