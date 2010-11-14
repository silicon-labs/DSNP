<?php
class OwnerCredController extends Controller
{
	var $function = array(
		'logout' => array(),
		'retftok' => array(
			array( 
				get => 'h',
				type => 'base64', 
				length => HASH_BASE64_SIZE 
			),
			array( 
				get => 'reqid',
				type => 'base64', 
				length => TOKEN_BASE64_SIZE
			)
		)
	);

	function logout()
	{
		session_destroy();
		setcookie("PHPSESSID", "", time() - 3600, "/");
		$this->userRedirect('/');
	}

	function retftok()
	{
		$hash = $this->args['h'];
		$reqid = $this->args['reqid'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->ftokenResponse( $this->USER[USER], $hash, $reqid );

		if ( ereg("^OK ([-A-Za-z0-9_]+) ([^ \t\r\n]*)",
				$connection->result, $regs ) )
		{
			$arg_ftoken = 'ftoken=' . urlencode( $regs[1] );
			$friend_id = $regs[2];
			$dest = "";
			if ( isset( $_GET['d'] ) )
				$dest = "&d=" . urlencode($_GET['d']);
			$this->redirect("{$friend_id}cred/sftoken?{$arg_ftoken}{$dest}" );
		}
		else {
			die ("ftoken response failed: {$connection->result}");
		}
	}
}
