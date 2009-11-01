<?php
class ImageController extends AppController
{
	var $name = 'Image';

	function beforeFilter()
	{
		$this->checkUser();
		$this->maybeActivateSession();
	}

	function view( $file )
	{
		if ( !$this->isOwnerOrFriend() ) {
			/* Not currently logged in. If there is a hash given we can try to
			 * log the user in. */
			if ( isset( $_REQUEST['h'] ) ) {
				$hash = $_REQUEST['h'];
				
				$hereFull = $this->hereFull();
				header( "Location: " . 
					Router::url( "/$this->USER_NAME/cred/sflogin?h=$hash&d=" . urlencode( $hereFull ) ) );
			}
		}

		if ( !ereg('^(img|thm|pub)-[0-9]*\.jpg$', $file ) )
			die("bad image");

		/* Find the image in the database. */

		Configure::write( 'debug', 0 );
		$path = "$this->CFG_PHOTO_DIR/$this->USER_NAME/$file";
		$this->set( 'path', $path );
		$this->render( 'view', 'image' );
	}
}
?>
