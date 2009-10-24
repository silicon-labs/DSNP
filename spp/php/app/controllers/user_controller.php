<?php

class UserController extends AppController
{
	var $name = 'User';

	function requireOwner()
	{
		if ( !$this->Session->valid() || $this->Session->read('auth') !== 'owner' )
			$this->cakeError("error403");

	}

	function requireFriend()
	{
		if ( !$this->Session->valid() || $this->Session->read('auth') !== 'friend' )
			$this->cakeError("error403");

	}

	function requireOwnerOrFriend()
	{
		if ( !$this->Session->valid() || ( 
				$this->Session->read('auth') !== 'owner' &&
				$this->Session->read('auth') !== 'friend' ) )
		{
			$this->cakeError("userNotFound");
		}
	}

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
		$user = $this->User->find( 'first', array('conditions' => 
				array('user' => $USER_NAME)));

		if ( $user == null )
			$this->cakeError("userNotFound", array('user' => $USER_NAME));

		$this->set( 'user', $user );
	}

	function indexUser()
	{
		global $USER_NAME;
		$this->setUser();

		# Load the user's sent friend requests
		$this->loadModel('SentFriendRequest');
		$sentFriendRequests = $this->SentFriendRequest->find('all', 
				array( 'conditions' => array( 'from_user' => $USER_NAME )));
		$this->set( 'sentFriendRequests', $sentFriendRequests );

		# Load the user's friend requests. 
		$this->loadModel('FriendRequest');
		$friendRequests = $this->FriendRequest->find( 'all',
				array( 'conditions' => array( 'for_user' => $USER_NAME )));
		$this->set( 'friendRequests', $friendRequests );

		# Load the friend list.
		$this->loadModel( 'FriendClaim' );
		$friendClaims = $this->FriendClaim->find('all', 
				array( 'conditions' => array( 'user' => $USER_NAME )));
		$this->set( 'friendClaims', $friendClaims );

		# Load the user's images.
		$this->loadModel('Image');
		$images = $this->Image->find('all', array( 'conditions' => 
				array( 'user' => $USER_NAME )));
		$this->set( 'images', $images );

		# Load up activity.
		$query = sprintf(
			"SELECT author_id, subject_id, time_published, type, resource_id, message " .
			"FROM received " .
			"WHERE for_user = '%s' " .
			"UNION " .
			"SELECT author_id, subject_id, time_published, type, resource_id, message " .
			"FROM published " . 
			"WHERE user = '%s' " .
			"UNION " .
			"SELECT author_id, subject_id, time_published, type, resource_id, message " .
			"FROM remote_published " .
			"WHERE user = '%s' " .
			"ORDER BY time_published DESC",
			mysql_real_escape_string($USER_NAME),
			mysql_real_escape_string($USER_NAME),
			mysql_real_escape_string($USER_NAME)
		);

		$activity = $this->User->query( $query );
		$this->set( 'activity', $activity );

		$this->render( 'owner' );
	}

	function indexFriend()
	{
		$this->setUser();
		$this->render( 'friend' );
	}

	function indexPublic()
	{
		$this->setUser();
		$this->render( 'public' );
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

	function slogin()
	{
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

	function img()
	{
		Configure::write( 'debug', 0 );

		global $CFG_PHOTO_DIR;
		global $USER_NAME;

		$this->requireOwnerOrFriend();

		$file = $this->params['pass'][0];

		if ( !ereg('^(img|thm|pub)-[0-9]*\.jpg$', $file ) )
			die("bad image");

		$path = "$CFG_PHOTO_DIR/$USER_NAME/$file";
		$this->set( 'path', $path );
		$this->render( 'img', 'img' );
	}
}

?>
