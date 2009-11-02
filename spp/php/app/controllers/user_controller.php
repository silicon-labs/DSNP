<?php

class UserController extends AppController
{
	var $name = 'User';

	function beforeFilter()
	{
		$this->checkUser();
		$this->maybeActivateSession();
	}

	function indexUser()
	{
		$this->set( 'auth', 'owner' );

		# Load the user's sent friend requests
		$this->loadModel('SentFriendRequest');
		$sentFriendRequests = $this->SentFriendRequest->find('all', 
				array( 'conditions' => array( 'from_user' => $this->USER_NAME )));
		$this->set( 'sentFriendRequests', $sentFriendRequests );

		# Load the user's friend requests. 
		$this->loadModel('FriendRequest');
		$friendRequests = $this->FriendRequest->find( 'all',
				array( 'conditions' => array( 'for_user' => $this->USER_NAME )));
		$this->set( 'friendRequests', $friendRequests );

		# Load the friend list.
		$this->loadModel( 'FriendClaim' );
		$friendClaims = $this->FriendClaim->find('all', 
				array( 'conditions' => array( 'user' => $this->USER_NAME )));
		$this->set( 'friendClaims', $friendClaims );

		# Load the user's images.
		$this->loadModel('Image');
		$images = $this->Image->find('all', array(
			'conditions' => 
				array( 'user' => $this->USER_NAME ),
			'order' => array( 'Image.seq_num DESC' )
		));
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
			mysql_real_escape_string($this->USER_NAME),
			mysql_real_escape_string($this->USER_NAME),
			mysql_real_escape_string($this->USER_NAME)
		);
		$activity = $this->User->query( $query );
		$this->set( 'activity', $activity );

		$this->render( 'owner' );
	}

	function indexFriend()
	{
		$this->set( 'auth', 'friend' );

		$identity = $this->Session->read('identity');
		$this->set( 'BROWSER_ID', $identity );
		define( 'BROWSER_ID', $identity );

		# Load the friend list.
		$this->loadModel( 'FriendClaim' );
		$friendClaims = $this->FriendClaim->find('all', 
				array( 'conditions' => array( 'user' => $this->USER_NAME )));
		$this->set( 'friendClaims', $friendClaims );

		# Load the user's images.
		$this->loadModel('Image');
		$images = $this->Image->find('all', array( 
			'conditions' => 
				array( 'user' => $this->USER_NAME ),
			'order' => array( 'Image.seq_num DESC' )
		));
		$this->set( 'images', $images );

		$query = sprintf(
			"SELECT author_id, subject_id, time_published, type, message " .
			"FROM published " . 
			"WHERE user = '%s' " .
			"UNION " .
			"SELECT author_id, subject_id, time_published, type, message " .
			"FROM remote_published " .
			"WHERE user = '%s' " .
			"ORDER BY time_published DESC",
			mysql_real_escape_string($this->USER_NAME),
			mysql_real_escape_string($this->USER_NAME)
		);
		$activity = $this->User->query( $query );
		$this->set( 'activity', $activity );

		$this->render( 'friend' );
	}

	function indexPublic()
	{
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

	function sflogin()
	{
		$hash = $_REQUEST['h'];

		if ( !$hash )
			die('no hash given');

		/* Maybe we are already logged in as this friend. */
		if ( isset( $_SESSION['auth'] ) && $_SESSION['auth'] == 'friend' && 
				isset( $_SESSION['hash'] ) && $_SESSION['hash'] == $hash ) {
			header( "Location: " . USER_PATH );
		}
		else {
			/* Not logged in as the hashed user. */
			$fp = fsockopen( 'localhost', CFG_PORT );
			if ( !$fp )
				exit(1);

			$send = 
				"SPP/0.1 " . CFG_URI . "\r\n" . 
				"comm_key " . CFG_COMM_KEY . "\r\n" .
				"ftoken_request " . $this->USER_NAME . " $hash\r\n";
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

		$fp = fsockopen( 'localhost', CFG_PORT );
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
			header("Location: ${friend_id}sftoken?${arg_ftoken}$dest" );
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

		$fp = fsockopen( 'localhost', CFG_PORT );
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

	function broadcast()
	{
		$this->requireOwner();

		/* User message */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: MSG\r\n" .
			"\r\n";
		$message = $_POST['message'];
		$len = strlen( $headers ) + strlen( $message );

		$this->loadModel('Published');
		$this->Published->save( array( 
			"user"  => $this->USER_NAME,
			"author_id" => CFG_URI . $this->USER_NAME . "/",
			"type" => "MSG",
			"message" => $message,
		));

		$fp = fsockopen( 'localhost', CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"submit_broadcast " . $this->USER_NAME . " $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);

		if ( ereg("^OK", $res, $regs) )
			$this->redirect( "/" . $this->USER_NAME . "/" );
		else
			echo $res;
	}

	function board()
	{
		$this->requireFriend();
		$BROWSER_ID = $_SESSION['identity'];

		/* User message. */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: BRD\r\n" .
			"\r\n";
		$message = $_POST['message'];
		$len = strlen( $headers ) + strlen( $message );

		$this->loadModel('Published');
		$this->Published->save( array( 
			'user' => $this->USER_NAME,
			'author_id' => $BROWSER_ID,
			'subject_id' => CFG_URI . $this->USER_NAME . "/",
			'type' => 'BRD',
			'message' => $message,
		));

		$fp = fsockopen( 'localhost', CFG_PORT );
		if ( !$fp )
			exit(1);

		$token = $_SESSION['token'];
		$hash = $_SESSION['hash'];

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"submit_remote_broadcast " . $this->USER_NAME . " $BROWSER_ID $hash $token $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);

		if ( ereg("^OK", $res, $regs) )
			$this->redirect( "/" . $this->USER_NAME . "/" );
		else
			echo $res;
	}

}
?>
