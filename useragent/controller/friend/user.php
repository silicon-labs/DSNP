<?php
class FriendUserController extends Controller
{
	var $function = array(
		'board' => array(
			array( post => 'message' )
		),
		'finish' => array(
			array( get => 'reqid' )
		),
	);

	function board()
	{
		$BROWSER = $_SESSION['BROWSER'];

		/* User message. */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: board-post\r\n" .
			"\r\n";

		$message = trim( $this->args['message'] );
		$len = strlen( $headers ) + strlen( $message );

		dbQuery( "
			INSERT INTO activity ( 
				user_id, author_id, published, type, message
			)
			VALUES ( %l, %e, true, 'BRD', %e )",
			$this->USER[ID],
			$BROWSER['id'],
			$message
		);

		$identity = $BROWSER[URI];
		$hash = $_SESSION['hash'];
		$token = $_SESSION['token'];

		$connection = new Connection;
		$connection->openLocalPriv();
		$connection->remoteBroadcastRequest( 
			$this->USER[USER], $identity, 
			$hash, $token, '-', $len,
			$headers, $message );

		if ( !$connection->success ) 
			die( $connection->result );
		$reqid = $connection->regs[1];

		$this->redirect( "${identity}user/flush?reqid=$reqid&backto=" . 
			urlencode( $this->USER[URI] )  );
	}

	function finish()
	{
		$reqid = $this->args['reqid'];

		$connection = new Connection;
		$connection->openLocalPriv();
		$connection->remoteBroadcastFinal(
			$this->USER[USER], $reqid );

		if ( !$connection->success )
			die( "remote_broadcast_final failed with $connection->result" );

		$this->userRedirect( "/" );
	}
};
