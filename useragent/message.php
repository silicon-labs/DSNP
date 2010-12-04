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

	function parse( $file, $len )
	{
		$headers = array();
		$left = $len;
		while ( true ) {
			$line = fgets( STDIN );
			if ( $line === "\r\n" ) {
				$left -= 2;
				break;
			}
			$left -= strlen( $line );

			/* Parse headers. */
			$replaced = preg_replace( '/Content-Type:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['content-type'] = trim($replaced);

			$replaced = preg_replace( '/Resource-Id:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['resource-id'] = trim($replaced);

			$replaced = preg_replace( '/Type:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['type'] = trim($replaced);

			if ( $left <= 0 )
				break;
		}
		$msg = fread( STDIN, $left );
		return array( $headers, $msg );
	}
};
?>
