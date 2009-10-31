<?php
class ImageController extends AppController
{
	var $name = 'Image';
	var $uses = array('User', 'Image');

	function beforeFilter()
	{
		$USER_NAME = $this->params['user'];
		$USER_PATH = CFG_PATH . "$USER_NAME/";
		$USER_URI = CFG_URI . "$USER_NAME/";

		define( 'USER_NAME', $USER_NAME );
		define( 'USER_PATH', $USER_PATH );
		define( 'USER_URI', $USER_URI );

		$this->checkUser();
		$this->maybeActivateSession();
	}

	function index( $file )
	{
		if ( !$this->isOwnerOrFriend() ) {
			$this->cakeError("notAuthorized", 
				array('url' => $this->params['url']['url'] ));
		}
		else {
			if ( !ereg('^(img|thm|pub)-[0-9]*\.jpg$', $file ) )
				die("bad image");

			/* Find the image in the database. */

			Configure::write( 'debug', 0 );
			$path = CFG_PHOTO_DIR . "/" . USER_NAME . "/$file";
			$this->set( 'path', $path );
			$this->render( 'index', 'image' );
		}
	}
}
?>
