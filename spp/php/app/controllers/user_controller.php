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
		$this->Session->activate( '/spp/' . USER_NAME . '/' );
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

	function checkUser()
	{
		$user = $this->User->find( 'first', array('conditions' => 
				array('user' => USER_NAME)));

		if ( $user == null )
			$this->cakeError("userNotFound", array('user' => USER_NAME));
	}

	function indexUser()
	{
		$this->checkUser();
		$this->set( 'auth', 'owner' );

		# Load the user's sent friend requests
		$this->loadModel('SentFriendRequest');
		$sentFriendRequests = $this->SentFriendRequest->find('all', 
				array( 'conditions' => array( 'from_user' => USER_NAME )));
		$this->set( 'sentFriendRequests', $sentFriendRequests );

		# Load the user's friend requests. 
		$this->loadModel('FriendRequest');
		$friendRequests = $this->FriendRequest->find( 'all',
				array( 'conditions' => array( 'for_user' => USER_NAME )));
		$this->set( 'friendRequests', $friendRequests );

		# Load the friend list.
		$this->loadModel( 'FriendClaim' );
		$friendClaims = $this->FriendClaim->find('all', 
				array( 'conditions' => array( 'user' => USER_NAME )));
		$this->set( 'friendClaims', $friendClaims );

		# Load the user's images.
		$this->loadModel('Image');
		$images = $this->Image->find('all', array(
			'conditions' => 
				array( 'user' => USER_NAME ),
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
			mysql_real_escape_string(USER_NAME),
			mysql_real_escape_string(USER_NAME),
			mysql_real_escape_string(USER_NAME)
		);
		$activity = $this->User->query( $query );
		$this->set( 'activity', $activity );

		$this->render( 'owner' );
	}

	function indexFriend()
	{
		$this->checkUser();
		$this->set( 'auth', 'friend' );

		$identity = $this->Session->read('identity');
		$this->set( 'BROWSER_ID', $identity );
		define( 'BROWSER_ID', $identity );

		# Load the friend list.
		$this->loadModel( 'FriendClaim' );
		$friendClaims = $this->FriendClaim->find('all', 
				array( 'conditions' => array( 'user' => USER_NAME )));
		$this->set( 'friendClaims', $friendClaims );

		# Load the user's images.
		$this->loadModel('Image');
		$images = $this->Image->find('all', array( 
			'conditions' => 
				array( 'user' => USER_NAME ),
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
			mysql_real_escape_string(USER_NAME),
			mysql_real_escape_string(USER_NAME)
		);
		$activity = $this->User->query( $query );
		$this->set( 'activity', $activity );

		$this->render( 'friend' );
	}

	function indexPublic()
	{
		$this->checkUser();
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

		$pass = $_POST['pass'];

		$fp = fsockopen( 'localhost', CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"login " . USER_NAME . " $pass\r\n";
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

			$this->redirect( "/" . USER_NAME . "/" );
		}
	}

	function img()
	{
		Configure::write( 'debug', 0 );

		global $CFG_PHOTO_DIR;

		$this->requireOwnerOrFriend();

		$file = $this->params['pass'][0];

		if ( !ereg('^(img|thm|pub)-[0-9]*\.jpg$', $file ) )
			die("bad image");

		$path = "$CFG_PHOTO_DIR/" . USER_NAME . "/$file";
		$this->set( 'path', $path );
		$this->render( 'img', 'img' );
	}

	function become()
	{
	}

	function sbecome()
	{
		$identity = $_POST['identity'];

		//require_once('../recaptcha-php-1.10/recaptchalib.php');
		//$resp = recaptcha_check_answer ($CFG_RC_PRIVATE_KEY,
		//              $_SERVER["REMOTE_ADDR"],
		//              $_POST["recaptcha_challenge_field"],
		//              $_POST["recaptcha_response_field"]);
		//
		//if (!$resp->is_valid) {
		//      die ("The reCAPTCHA wasn't entered correctly. Go back and try it again." .
		//                      "(reCAPTCHA said: " . $resp->error . ")");
		//}

		$fp = fsockopen( 'localhost', CFG_PORT );
		if ( !$fp )
			die( "!!! There was a problem connecting to the local SPP server.");
		
		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"relid_request " . USER_NAME . " $identity\r\n";
		fwrite($fp, $send);
		
		$res = fgets($fp);

		if ( ereg("^OK ([-A-Za-z0-9_]+)", $res, $regs) ) {
			$arg_identity = 'identity=' . urlencode( USER_URI );
			$arg_reqid = 'fr_reqid=' . urlencode( $regs[1] );

			header("Location: ${identity}retrelid?${arg_identity}&${arg_reqid}" );
		}
		else if ( ereg("^ERROR ([0-9]+)", $res, $regs) ) {
			die( "!!! There was an error:<br>" .
			$ERROR[$regs[1]] . "<br>" .
			"Check that the URI you submitted is correct.");
		}
		else {
			die( "!!! The local SPP server did not respond. How rude.<br>" . 
				"Check that the URI you submitted is correct.");
		}
	}

	function retrelid()
	{
		$this->requireOwner();

		$identity = $_GET['identity'];
		$fr_reqid = $_GET['fr_reqid'];

		$fp = fsockopen( 'localhost', CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"relid_response " . USER_NAME . " $fr_reqid $identity\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);

		if ( ereg("^OK ([-A-Za-z0-9_]+)", $res, $regs) ) {
			$arg_identity = 'identity=' . urlencode( USER_URI );
			$arg_reqid = 'reqid=' . urlencode( $regs[1] );

			header("Location: ${identity}frfinal?${arg_identity}&${arg_reqid}" );
		}
		else {
			echo $res;
		}
	}

	function frfinal()
	{
		$identity = $_GET['identity'];
		$reqid = $_GET['reqid'];

		$fp = fsockopen( 'localhost', CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"friend_final " . USER_NAME . " $reqid $identity\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);

		if ( ereg("^OK", $res) ) {
			header("Location: " . USER_URI );
		}
		else {
			echo $res;
		}
	}

	function answer()
	{
		$this->requireOwner();

		$reqid = $_GET['reqid'];

		$query = sprintf(
			"DELETE FROM friend_request ".
			"WHERE for_user = '%s' AND reqid = '%s'",
			USER_NAME, $reqid );

		$this->User->query( $query );

		$fp = fsockopen( 'localhost', CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"accept_friend " . USER_NAME . " $reqid\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK", $res) ) {
			echo "FAILURE *** Friend accept failed with: <br>";
			echo $res;
		}
		else {
			header("Location: " . USER_URI );
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

		$fp = fsockopen( 'localhost', CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"ftoken_response " . USER_NAME . " $hash $reqid\r\n";
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
				$this->redirect( "/" . USER_NAME . "/" );
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
			"user"  => USER_NAME,
			"author_id" => CFG_URI . USER_NAME . "/",
			"type" => "MSG",
			"message" => $message,
		));

		$fp = fsockopen( 'localhost', CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"submit_broadcast " . USER_NAME . " 0 $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);

		if ( ereg("^OK", $res, $regs) )
			$this->redirect( "/" . USER_NAME . "/" );
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
			'user' => USER_NAME,
			'author_id' => $BROWSER_ID,
			'subject_id' => CFG_URI . USER_NAME . "/",
			'type' => 'MSG',
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
			"submit_remote_broadcast " . USER_NAME . " $BROWSER_ID $hash $token BRD $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $message, strlen($message) );
		fwrite( $fp, "\r\n", 2 );

		$res = fgets($fp);

		if ( ereg("^OK", $res, $regs) )
			$this->redirect( "/" . USER_NAME . "/" );
		else
			echo $res;
	}

	function upload()
	{
		$max_image_size = 10485760;

		$this->requireOwner();

		if ( $_FILES['photo']['size'] > $max_image_size )
			die("image excedes max size of $max_image_size bytes");

		# Validate it as an image.
		$image_size = @getimagesize( $_FILES['photo']['tmp_name'] );
		if ( ! $image_size )
			die( "file doesn't appear to be a valid image" );

		$this->loadModel('Image');
		$this->Image->save( array( 
			'user' => USER_NAME,
			'rows' => $image_size[1], 
			'cols' => $image_size[0], 
			'mime_type' => $image_size['mime']
		));

		$result = $this->User->query( "SELECT last_insert_id() as id" );
		$id = $result[0][0]['id'];
		$path = CFG_PHOTO_DIR . "/" . USER_NAME . "/img-$id.jpg";

		if ( ! @move_uploaded_file( $_FILES['photo']['tmp_name'], $path ) )
			die( "bad image file" );

		$thumb = CFG_PHOTO_DIR . "/" . USER_NAME . "/thm-$id.jpg";

		system(CFG_IM_CONVERT . " " .
			"-define jpeg:preserve-settings " .
			"-size 120x120 " .
			$path . " " .
			"-resize 120x120 " .
			"+profile '*' " .
			$thumb );

		$this->loadModel('Published');
		$this->Published->save( array( 
			'user' => USER_NAME,
			'author_id' => CFG_URI . USER_NAME . "/",
			'type' => "PHT",
			'message' => "thm-$id.jpg"
		));

		$fp = fsockopen( 'localhost', CFG_PORT );
		if ( !$fp )
			exit(1);

		$MAX_BRD_PHOTO_SIZE = 16384;
		$file = fopen( $thumb, "rb" );
		$data = fread( $file, $MAX_BRD_PHOTO_SIZE );
		fclose( $file );

		$headers = 
			"Content-Type: image/jpg\r\n" .
			"Resource-Id: $id\r\n" .
			"Type: PHT\r\n" .
			"\r\n";
		$len = strlen( $headers ) + strlen( $data );

		$send = 
			"SPP/0.1 " . CFG_URI . "\r\n" . 
			"comm_key " . CFG_COMM_KEY . "\r\n" .
			"submit_broadcast " . USER_NAME . " $id $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $data, strlen($data) );
		fwrite( $fp, "\r\n", 2 );

		$this->redirect( "/" . USER_NAME . "/" );
	}

	function logout()
	{
		$this->Session->destroy();
		$this->redirect( "/" . USER_NAME . "/" );
	}
}
?>
