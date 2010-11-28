<?php

require( ROOT . DS . 'controller/cred.php' );

class FriendCredController extends CredController
{
	var $function = array(
		'logout' => array(),
		'sflogin' => array(
			array( 
				get => 'h',
				type => 'base64', 
				length => HASH_BASE64_SIZE 
			)
		),
	);

	function logout()
	{
		session_destroy();
		setcookie("PHPSESSID", "", time() - 3600, "/");
		$this->userRedirect('/');
	}

	function sflogin()
	{
		/* Already logged in as a friend. If it is the same friend we can keep
		 * the login active. If not we need to restart the whole login again.
		 * */
		$hash = $this->args[h];
		if ( isset( $_SESSION['hash'] ) && $_SESSION['hash'] === $hash ) {
			#//die("HELLO THERE");
			$this->userRedirect( "/" );
		}
		else {
			$this->destroySession();
			$this->submitFriendLogin( $hash );
		}
	}
}
?>
