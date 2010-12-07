<?php

require( ROOT . DS . 'controller/image.php' );

class FriendImageController extends ImageController
{
	var $function = array(
		'view' => array(
			array(
				route => 'file',
				N => 2,
				regex => '/^(img|thm|pub)-[0-9]*\.jpg$/'
			)
		),
	);

	function view()
	{
		$file = $this->args['file'];
		$this->viewImage( $file );
	}
}
?>
