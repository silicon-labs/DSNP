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

		dbQuery( "
			INSERT INTO activity ( user_id, published, type, message )
			VALUES ( %e, true, 'MSG', %e )", $this->USER[ID], $message );

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
