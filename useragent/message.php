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
};
?>
