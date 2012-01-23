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
		'display' => array(
			array(
				route => 'file',
				N => 2,
				regex => '/^(img|thm|pub)-[0-9]*\.jpg$/'
			)
		),
		'stream' => array(),
	);

	function upload()
	{
		$maxImageSize = 10485760;

		if ( $_FILES['photo']['size'] > $maxImageSize )
			$this->userError( "image excedes max size of $maxImageSize bytes", "" );

		# Validate it as an image.
		$imageSize = @getimagesize( $_FILES['photo']['tmp_name'] );
		if ( ! $imageSize )
			$this->userError( "file doesn't appear to be a valid image", "" );

		# Make a row in the db ofor the image.
		dbQuery( "
			INSERT INTO image ( user_id, rows, cols, mime_type )
			VALUES ( %l, %l, %l, %e );",
			$this->USER['USER_ID'], 
			$imageSize[1], $imageSize[0],
			$imageSize['mime']
		);

		# Get the id for the row, will use it in the filename.
		$imageId = lastInsertId();

		# Make a row for the publication.
		dbQuery( "
			INSERT INTO publication ( user_id, author_id )
			VALUES ( %l, %l )", 
			$this->USER['USER_ID'], 
			$this->USER['RELATIONSHIP_ID']
		);

		$publicationId = lastInsertId();

		# Where the user's photos go.
		$dir = $this->imageDir();

		# Create the photo dir if not present.
		if ( !file_exists( $dir ) )
			mkdir( $dir );

		$path = "$dir/img-$imageId.jpg";
		$thumb = "$dir/thm-$imageId.jpg";

		$remoteResource      = $this->userLoc( "/image/view/img-$imageId.jpg" );
		$remotePresentation  = $this->userLoc( "/image/display/img-$imageId.jpg" );

		$localThumbnail      = "/image/view/thm-$imageId.jpg";
		$localResource       = "/image/view/img-$imageId.jpg";
		$localPresentation   = "/image/display/img-$imageId.jpg";

		# A move preserve original perms. Take advantage of the group super bit
		# by using a copy.
		$src = $_FILES['photo']['tmp_name'];

		/* Need mask that include group write. */
		umask( 0007 );
		if ( is_uploaded_file( $src ) ) {
			copy( $src, $path );
			unlink( $src );
		}

		# FIXME: check results.
		global $CONVERT;
		system( $CONVERT . " " .
			"-define jpeg:preserve-settings " .
			"-size 120x120 " .
			$path . " " .
			"-resize 120x120 " .
			"+profile '*' " .
			$thumb );

		dbQuery("
			INSERT IGNORE INTO activity (
				user_id, publisher_id, pub_type, message_id,
				local_thumbnail, local_resource, local_presentation
			)
			VALUES ( %l, %l, %l, %e, %e, %e, %e )",
			$this->USER['USER_ID'], 
			$this->USER['RELATIONSHIP_ID'],
			PUB_TYPE_PHOTO, 
			$publicationId,
			$localThumbnail, 
			$localResource, 
			$localPresentation
		);

		$message = new Message;
		$message->photoUpload( $publicationId, $remoteResource,
				$remotePresentation, $imageId, $thumb );

		$connection = new Connection;
		$connection->openLocal();

		$connection->submitBroadcast( 
			$_SESSION['token'], $message->message );

		if ( $connection->success )
			$this->userRedirect( "/" );
		else {
			$this->userError( "submit_broadcast failed " .
					"with $connection->result", "" );
		}

		$this->userRedirect( '/image/stream' );
	}

	function view()
	{
		$file = $this->args['file'];
		$this->viewImage( $file );
	}

	function display()
	{
		$file = $this->args['file'];
		$this->vars['file'] = $file;
	}

	function stream()
	{
		$start = $this->args[start];

		# Load the user's images.
		$images = dbQuery( "
			SELECT * FROM image WHERE user_id = %L 
			ORDER BY seq_num DESC LIMIT 30",
			$this->USER['USER_ID'] );
		$this->vars['images'] = $images;
	}
}
?>
