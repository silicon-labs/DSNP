<?php
class ImageController extends AppController
{
	var $name = 'Image';

	function beforeFilter()
	{
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
			$path = "$this->CFG_PHOTO_DIR/$this->USER_NAME/$file";
			$this->set( 'path', $path );
			$this->render( 'index', 'image' );
		}
	}
}
?>
