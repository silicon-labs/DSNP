<?php

require( ROOT . DS . 'controller/cred.php' );

class FriendCredController extends CredController
{
	var $function = array(
		'logout' => array(),
	);

	function logout()
	{
		session_destroy();
		setcookie("PHPSESSID", "", time() - 3600, "/");
		$this->userRedirect('/');
	}
}

?>
