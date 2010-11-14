<?php

class UserController extends AppController
{
	var $name = 'User';
	var $helpers = array("html", "text");

	function beforeFilter()
	{
		$this->checkUserMaybeActivateSession();
	}

	function indexOwner()
	{
		if ( isset( $_GET['start'] ) )
			$start = $_GET['start'];
		else
			$start = 0;

		$sentFriendRequests = dbQuery( 
			"SELECT * FROM sent_friend_request WHERE from_user = %e", 
			$this->USER_NAME );
		$this->set( 'sentFriendRequests', $sentFriendRequests );

		# Load the user's friend requests. 
		$friendRequests = dbQuery( 
			"SELECT * FROM friend_request WHERE for_user = %e",
			$this->USER_NAME );
		$this->set( 'friendRequests', $friendRequests );

		# Load the friend list.
		$friendClaims = dbQuery(
			"SELECT * FROM friend_claim WHERE user_id = %l",
			$this->USER_ID );
		$this->set( 'friendClaims', $friendClaims );

		# Load the user's images.
		$images = dbQuery( "
			SELECT * FROM image WHERE user = %e 
			ORDER BY seq_num DESC LIMIT 30
			", $this->USER_NAME );
		$this->set( 'images', $images );

		$activity = dbQuery( "
			SELECT 
				activity.*, 
				author_fc.identity AS author_identity,
				author_fc.name AS author_name,
				subject_fc.identity AS subject_identity,
				subject_fc.name AS subject_name
			FROM activity 
			LEFT OUTER JOIN friend_claim AS author_fc ON activity.author_id = author_fc.id
			LEFT OUTER JOIN friend_claim AS subject_fc ON activity.subject_id = subject_fc.id
			WHERE activity.user_id = %l
			ORDER BY time_published DESC LIMIT %l
			",
			$this->USER_ID, $start + Configure::read('activity_size') );
		$this->set( 'start', $start );
		$this->set( 'activity', $activity );

		$this->render( 'owner' );
	}

	function indexFriend()
	{
		if ( isset( $_GET['start'] ) )
			$start = $_GET['start'];
		else
			$start = 0;

		$BROWSER = $this->Session->read('BROWSER');
		$this->set( 'BROWSER', $BROWSER );

		# Load the friend list.
		$friendClaims = dbQuery( 
			"SELECT * FROM friend_claim WHERE user_id = %l",
			$this->USER_ID );
		$this->set( 'friendClaims', $friendClaims );

		# Load the user's images.
		$images = dbQuery(
			"SELECT * FROM image WHERE user = %e",
			$this->USER_NAME );
		$this->set( 'images', $images );

		$activity = dbQuery( "
			SELECT 
				activity.*,
				author_fc.identity AS author_identity,
				author_fc.name AS author_name,
				subject_fc.identity AS subject_identity,
				subject_fc.name AS subject_name
			FROM activity 
			LEFT OUTER JOIN friend_claim AS author_fc ON activity.author_id = author_fc.id
			LEFT OUTER JOIN friend_claim AS subject_fc ON activity.subject_id = subject_fc.id
			WHERE activity.user_id = %l
			ORDER BY time_published LIMIT %l
			",
			$this->USER_ID, $start + Configure::read('activity_size') );
		$this->set( 'start', $start );
		$this->set( 'activity', $activity );

		$this->render( 'friend' );
	}

	function indexPublic()
	{
		$this->render( 'public' );
	}


	function index()
	{
		if ( $this->ROLE === 'owner' )
			$this->indexOwner();
		else if ( $this->ROLE === 'friend' )
			$this->indexFriend();
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
		$message = trim( $_POST['message'] );
		$len = strlen( $headers ) + strlen( $message );

		$this->loadModel('Activity');
		$this->Activity->save( array( 
			"user_id"  => $this->USER_ID,
			'published' => 'true',
			"type" => "MSG",
			"message" => $message,
		));

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"submit_broadcast $this->USER_NAME - $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);

		if ( ereg("^OK", $res, $regs) )
			$this->redirect( "/$this->USER_NAME/" );
		else
			die( "submit_broadcast failed with $res" );
	}

	function board()
	{
		$this->requireFriend();
		$BROWSER = $this->Session->read('BROWSER');

		/* User message. */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: board-post\r\n" .
			"\r\n";
		$message = trim( $_POST['message'] );
		$len = strlen( $headers ) + strlen( $message );

		$this->loadModel('Activity');
		$this->Activity->save( array( 
			'user_id'  => $this->USER_ID,
			'author_id' => $BROWSER['id'],
			'published' => 'true',
			'type' => 'BRD',
			'message' => $message,
		));

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$identity = $BROWSER['identity'];
		$hash = $_SESSION['hash'];
		$token = $_SESSION['token'];

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"remote_broadcast_request $this->USER_NAME $identity $hash $token - $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);

		if ( !ereg("^OK ([-A-Za-z0-9_]+)", $res, $regs) )
			die( $res );
		$reqid = $regs[1];

		$this->redirect( "${identity}user/flush?reqid=$reqid&backto=" . 
			urlencode( $this->USER['identity'] )  );
	}

	function flush()
	{
		$this->requireOwner();
		$reqid = $_REQUEST['reqid'];
		$backto = $_REQUEST['backto'];

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"remote_broadcast_response $this->USER_NAME $reqid\r\n";

		fwrite( $fp, $send );
		$res = fgets($fp);

		if ( !ereg("^OK ([-A-Za-z0-9_]+)", $res, $regs) )
			die( "remote_broadcast_response failed with $res ");
		$reqid = $regs[1];

		$this->redirect( "${backto}user/finish?reqid=$reqid" );
	}

	function finish()
	{
		$this->requireFriend();
		$reqid = $_REQUEST['reqid'];

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"remote_broadcast_final $this->USER_NAME $reqid\r\n";

		fwrite( $fp, $send );
		$res = fgets($fp);

		if ( !ereg("^OK", $res, $regs) )
			die( "remote_broadcast_final failed with $res" );

		$this->redirect( "/$this->USER_NAME/" );
	}

	function edit()
	{
		$this->requireOwner();
		$user = dbQuery( "SELECT * FROM user WHERE user = %e", $this->USER_NAME );
		$this->set( 'user', $user );
	}

	function sedit()
	{
		$this->requireOwner();

		$id = $_POST['id'];
		$name = $_POST['name'];
		$email = $_POST['email'];

		if ( preg_match( '/^[ \t\n]*$/', $name ) )
			$name = null;
		if ( preg_match( '/^[ \t\n]*$/', $email ) )
			$email = null;

		if ( $id === $this->USER_ID )
			dbQuery( "UPDATE user SET name = %e, email = %e WHERE id = %l", $name, $email, $this->USER_ID );

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
			"submit_broadcast $this->USER_NAME - $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);

				$this->VALID_USER = $this->Session->read('VALID_USER');

		if ( ! ereg("^OK", $res, $regs) )
			die( $res );

		/* Invalidate the user data in the session so it is reloaded on the
		 * next page load. */
		$this->Session->write( 'VALID_USER', false );

		$this->redirect( "/$this->USER_NAME/" );
	}
}
?>
