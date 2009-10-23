<?php

class HomeController extends AppController
{
	var $name = 'Home';

	function beforeFilter()
	{
		global $USER_NAME;
		$this->Session->activate( '/spp/' . $USER_NAME . '/' );
	}

	function index()
	{

	}
}

?>
