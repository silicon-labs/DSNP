<?php
class Message
{
	var $message;

	function nameChange( $newName )
	{
		/* User message */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: name-change\r\n" .
			"\r\n";

		$this->message = $headers . $newName;
	}

	function photoUpload( $id, $fileName )
	{
		$headers = 
			"Content-Type: image/jpg\r\n" .
			"Resource-Id: $id\r\n" .
			"Type: photo-upload\r\n" .
			"\r\n";

		$MAX_BRD_PHOTO_SIZE = 16384;
		$file = fopen( $fileName, "rb" );
		$data = fread( $file, $MAX_BRD_PHOTO_SIZE );
		fclose( $file );

		$this->message = $headers . $data;
	}
	
	function broadcast( $text )
	{
		/* User message */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: broadcast\r\n" .
			"\r\n";

		$this->message = $headers . $text;
	}

	function boardPost( $text )
	{
		/* User message. */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: board-post\r\n" .
			"\r\n";

		$this->message = $headers . $text;
	}
};
?>
