<?php
class OwnerUserController extends Controller
{
	var $function = array(
		'broadcast' => array(),
	);

	function broadcast()
	{
		/* User message */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: broadcast\r\n" .
			"\r\n";
		$message = trim( $_POST['message'] );
		$len = strlen( $headers ) + strlen( $message );

#		$this->loadModel('Activity');
#		$this->Activity->save( array( 
#			"user_id"  => $this->USER_ID,
#			'published' => 'true',
#			"type" => "MSG",
#			"message" => $message,
#		));

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->submitBroadcast( 
			$this->USER[USER],  '-', $len, $headers, $message );

		if ( ereg("^OK", $connection->result, $regs) )
			$this->userRedirect( "/" );
		else
			die( "submit_broadcast failed with $connection->result" );
	}
}
?>
