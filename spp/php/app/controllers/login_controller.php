<?php
class LoginController extends AppController 
{
	var $name = 'Login';

	function beforeFilter()
	{
		global $USER_NAME;
		$this->Session->activate( '/spp/' . $USER_NAME . '/' );
	}

	function index() {}

	function submit()  {
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

			header( "Location: $USER_PATH" );
		}
	}
}
?>
