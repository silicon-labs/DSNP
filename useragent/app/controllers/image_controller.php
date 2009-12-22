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
		$path = DATA_DIR . "/$this->USER_NAME/$file";
		$this->set( 'path', $path );
		$this->render( 'view', 'image' );
	}

	function upload()
	{
		$this->requireOwner();
		$max_image_size = 10485760;

		if ( $_FILES['photo']['size'] > $max_image_size )
			die("image excedes max size of $max_image_size bytes");

		# Validate it as an image.
		$image_size = @getimagesize( $_FILES['photo']['tmp_name'] );
		if ( ! $image_size )
			die( "file doesn't appear to be a valid image" );

		$this->loadModel('Image');
		$this->Image->save( array( 
			'user' => $this->USER_NAME,
			'rows' => $image_size[1], 
			'cols' => $image_size[0], 
			'mime_type' => $image_size['mime']
		));

		$result = $this->User->query( "SELECT last_insert_id() as id" );
		$id = $result[0][0]['id'];
		$path = DATA_DIR . "/$this->USER_NAME/img-$id.jpg";

		if ( ! @move_uploaded_file( $_FILES['photo']['tmp_name'], $path ) )
			die( "bad image file" );

		$thumb = DATA_DIR . "/$this->USER_NAME/thm-$id.jpg";

		system($this->CFG_IM_CONVERT . " " .
			"-define jpeg:preserve-settings " .
			"-size 120x120 " .
			$path . " " .
			"-resize 120x120 " .
			"+profile '*' " .
			$thumb );

		$this->loadModel('Published');
		$this->Published->save( array( 
			'user' => $this->USER_NAME,
			'author_id' => $this->CFG_URI . $this->USER_NAME . "/",
			'type' => "PHT",
			'message' => "thm-$id.jpg"
		));

		$this->loadModel('Activity');
		$this->Activity->save( array( 
			'user_id' => $this->USER_ID,
			'published' => 'true',
			'type' => 'PHT',
			'message' => "thm-$id.jpg",
			'local_resid' => $id
		));

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$MAX_BRD_PHOTO_SIZE = 16384;
		$file = fopen( $thumb, "rb" );
		$data = fread( $file, $MAX_BRD_PHOTO_SIZE );
		fclose( $file );

		$headers = 
			"Content-Type: image/jpg\r\n" .
			"Resource-Id: $id\r\n" .
			"Type: photo-upload\r\n" .
			"\r\n";
		$len = strlen( $headers ) + strlen( $data );

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"submit_broadcast $this->USER_NAME friend $len\r\n";

		fwrite( $fp, $send );
		fwrite( $fp, $headers, strlen($headers) );
		fwrite( $fp, $data, strlen($data) );
		fwrite( $fp, "\r\n", 2 );

		$this->redirect( "/$this->USER_NAME/" );
	}
}
?>
