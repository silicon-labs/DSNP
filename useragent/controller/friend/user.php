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
		$text = trim( $this->args['message'] );

		dbQuery( "
			INSERT INTO activity ( 
				user_id, author_id, published, type, message
			)
			VALUES ( %l, %e, true, 'BRD', %e )",
			$this->USER['ID'],
			$BROWSER['ID'],
			$text
		);

		$identity = $BROWSER[URI];
		$hash = $_SESSION['hash'];
		$token = $_SESSION['token'];

		$message = new Message;
		$message->boardPost( $text );

		$connection = new Connection;
		$connection->openLocalPriv();
		$connection->remoteBroadcastRequest( 
			$this->USER[USER], $identity, 
			$hash, $token, '-',
			$message->message );

		if ( !$connection->success ) 
			$this->userError( $connection->result, "" );
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

		if ( !$connection->success ) {
			$this->userError( "remote_broadcast_final " .
				"failed with $connection->result", "" );
		}

		$this->userRedirect( "/" );
	}
};
