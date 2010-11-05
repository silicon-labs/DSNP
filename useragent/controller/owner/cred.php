<?php
class OwnerCredController extends Controller
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
