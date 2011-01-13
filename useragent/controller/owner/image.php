<?php

require( ROOT . DS . 'controller/image.php' );

class OwnerImageController extends ImageController
{
	var $function = array(
		'upload' => array(),
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

	function upload()
	{
		$max_image_size = 10485760;

		if ( $_FILES['photo']['size'] > $max_image_size )
			$this->userError( "image excedes max size of $max_image_size bytes", "" );

		# Validate it as an image.
		$image_size = @getimagesize( $_FILES['photo']['tmp_name'] );
		if ( ! $image_size )
			$this->userError( "file doesn't appear to be a valid image", "" );

		# Make a row in the db ofor the image.
		dbQuery( "
			INSERT INTO image ( user, rows, cols, mime_type )
			VALUES ( %e, %l, %l, %e );",
			$this->USER[USER], 
			$image_size[1], $image_size[0],
			$image_size['mime']
		);

		# Get the id for the row, will use it in the filename.
		$result = dbQuery( "SELECT last_insert_id() AS id" );
		$id = $result[0]['id'];

		# Where the user's photos go.
		$dir = "{$this->CFG[PHOTO_DIR]}/{$this->USER[USER]}";

		# Create the photo dir if not present.
		if ( !file_exists( $dir ) )
			mkdir( $dir );

		$path = "$dir/img-$id.jpg";
		$thumb = "$dir/thm-$id.jpg";

		if ( ! @move_uploaded_file( $_FILES['photo']['tmp_name'], $path ) )
			$this->userError( "unable to move image file", "" );

		# FIXME: check results.
		system($this->CFG[IM_CONVERT] . " " .
			"-define jpeg:preserve-settings " .
			"-size 120x120 " .
			$path . " " .
			"-resize 120x120 " .
			"+profile '*' " .
			$thumb );

		dbQuery("
			INSERT INTO activity ( 
				user_id, published, type, message, local_resid )
			VALUES ( %l, true, 'PHT', %e, %l )",
			$this->USER[ID], "thm-$id.jpg", $id );

		$message = new Message;
		$message->photoUpload( $id, $thumb );

		$connection = new Connection;
		$connection->openLocal();

		$connection->submitBroadcast( 
			$this->USER[USER], '-', $message->message );

		if ( $connection->success )
			$this->userRedirect( "/" );
		else {
			$this->userError( "submit_broadcast failed " .
					"with $connection->result", "" );
		}

		$this->userRedirect( '/' );
	}
}
?>
