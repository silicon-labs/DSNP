<?php

class UserController extends AppController
{
	var $name = 'User';

	function beforeFilter()
	{
		$this->checkUser();
		$this->maybeActivateSession();
	}

	function indexOwner()
	{
		$this->set( 'auth', 'owner' );
		$this->privName();

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
		$this->privName();

		$identity = $this->Session->read('BROWSER_ID');
		$this->set( 'BROWSER_ID', $identity );

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
				$this->indexOwner();
			else if ( $this->Session->read('auth') === 'friend' )
				$this->indexFriend();
			else
				$this->indexPublic();
		}
		else
			$this->indexPublic();
	}

	function broadcast()
	{
		$this->requireOwner();

		/* User message */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: broadcast\r\n" .
			"\r\n";
		$message = $_POST['message'];
		$len = strlen( $headers ) + strlen( $message );

		$this->loadModel('Published');
		$this->Published->save( array( 
			"user"  => $this->USER_NAME,
			"author_id" => "$this->CFG_URI$this->USER_NAME/",
			"type" => "MSG",
			"message" => $message,
		));

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"submit_broadcast $this->USER_NAME $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);

		if ( ereg("^OK", $res, $regs) )
			$this->redirect( "/$this->USER_NAME/" );
		else
			echo $res;
	}

	function board()
	{
		$this->requireFriend();
		$BROWSER_ID = $this->Session->read('BROWSER_ID');

		/* User message. */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: board-post\r\n" .
			"\r\n";
		$message = $_POST['message'];
		$len = strlen( $headers ) + strlen( $message );

		$this->loadModel('Published');
		$this->Published->save( array( 
			'user' => $this->USER_NAME,
			'author_id' => $BROWSER_ID,
			'subject_id' => $this->CFG_URI . $this->USER_NAME . "/",
			'type' => 'BRD',
			'message' => $message,
		));

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$token = $_SESSION['token'];
		$hash = $_SESSION['hash'];

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"submit_remote_broadcast $this->USER_NAME $BROWSER_ID $hash $token $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);

		if ( ereg("^OK", $res, $regs) )
			$this->redirect( "/$this->USER_NAME/" );
		else
			echo $res;
	}

	function edit()
	{
		$this->requireOwner();
		$this->data = $this->User->find('first', 
				array( 'conditions' => array( 'user' => $this->USER_NAME )));
	}

	function sedit()
	{
		$this->requireOwner();

		if ( $this->data['User']['id'] == $this->USER_ID )
			$this->User->save( $this->data, true, array('name', 'email') );

		/* User message */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: name-change\r\n" .
			"\r\n";
		$message = $this->data['User']['name'];
		$len = strlen( $headers ) + strlen( $message );

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"submit_broadcast $this->USER_NAME $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);

		if ( ereg("^OK", $res, $regs) )
			$this->redirect( "/$this->USER_NAME/" );
		else
			echo $res;

		header( "Location: " . Router::url( "/$this->USER_NAME/" ) );
	}
}
?>
