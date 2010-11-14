<?php
class FriendUserController extends Controller
{
	var $function = array(
		'board' => array(
			array( post => 'message' )
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

		$identity = $BROWSER['identity'];
		$hash = $_SESSION['hash'];
		$token = $_SESSION['token'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->remoteBroadcastRequest( 
			$this->USER[USER], $identity, 
			$hash, $token, '-', $len,
			$headers, $message );

		if ( !ereg("^OK ([-A-Za-z0-9_]+)", $connection->result, $regs ) )
			die( $connection->result );
		$reqid = $regs[1];

		$this->redirect( "${identity}user/flush?reqid=$reqid&backto=" . 
			urlencode( $this->USER['identity'] )  );
	}
};
