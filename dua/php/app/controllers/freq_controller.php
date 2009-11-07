<?php

class FreqController extends AppController
{
	var $name = 'Freq';
	var $uses = array();

	function beforeFilter()
	{
		$this->checkUser();
		$this->maybeActivateSession();
	}

	function index()
	{
		$this->render('submit');
	}

	function submit()
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

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			die( "!!! There was a problem connecting to the local SPP server.");
		
		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"relid_request $this->USER_NAME $identity\r\n";
		fwrite($fp, $send);
		
		$res = fgets($fp);

		if ( ereg("^OK ([-A-Za-z0-9_]+)", $res, $regs) ) {
			$arg_identity = 'identity=' . urlencode( $this->USER_URI );
			$arg_reqid = 'fr_reqid=' . urlencode( $regs[1] );

			header("Location: ${identity}freq/retrelid?${arg_identity}&${arg_reqid}" );
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

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"relid_response $this->USER_NAME $fr_reqid $identity\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);

		if ( ereg("^OK ([-A-Za-z0-9_]+)", $res, $regs) ) {
			$arg_identity = 'identity=' . urlencode( $this->USER_URI );
			$arg_reqid = 'reqid=' . urlencode( $regs[1] );

			header("Location: ${identity}freq/frfinal?${arg_identity}&${arg_reqid}" );
		}
		else {
			echo $res;
		}
	}

	function frfinal()
	{
		$identity = $_GET['identity'];
		$reqid = $_GET['reqid'];

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"friend_final $this->USER_NAME $reqid $identity\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);

		if ( ereg("^OK", $res) ) {
			header("Location: $this->USER_URI" );
		}
		else {
			echo $res;
		}
	}

	function answer()
	{
		$this->requireOwner();

		$reqid = $_GET['reqid'];

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"accept_friend $this->USER_NAME $reqid\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK", $res) )
			die( "FAILURE *** Friend accept failed with: <br>" . $res );

		$query = sprintf(
			"DELETE FROM friend_request ".
			"WHERE for_user = '%s' AND reqid = '%s'",
			$this->USER_NAME, $reqid );

		$this->User->query( $query );

		header("Location: $this->USER_URI" );
	}
}

?>
