<?php
class OwnerUserController extends Controller
{
	var $function = array(
		'broadcast' => array(),
		'flush' => array(
			array( 
				get => 'reqid', 
				type => 'base64', 
				length => TOKEN_BASE64_SIZE
			),
			array(
				get => 'backto'
			)
		)
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

	function flush()
	{
		$reqid = $this->args['reqid'];
		$backto = $this->args['backto'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->remoteBroadcastResponse(
			$this->USER[USER], $reqid );

		if ( !ereg("^OK ([-A-Za-z0-9_]+)", $connection->result, $regs) )
			die( "remote_broadcast_response failed with $res ");
		$reqid = $regs[1];

		$this->redirect( "${backto}user/finish?reqid=$reqid" );
	}
}
?>
