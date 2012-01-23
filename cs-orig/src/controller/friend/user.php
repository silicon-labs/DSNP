<?php
class FriendUserController extends Controller
{
	var $function = array(
		'board' => array(
			array( post => 'message' )
		),
		'finish' => array(
			array( get => 'dsnp_reqid' )
		),
	);

	function board()
	{
		$BROWSER = $_SESSION['BROWSER'];
		$text = trim( $this->args['message'] );

		dbQuery( "
			INSERT INTO publication ( user_id, author_id )
			VALUES ( %l, %l )", 
			$this->USER['USER_ID'], 
			$this->USER['RELATIONSHIP_ID']
		);
		$publicationId = lastInsertId();

		dbQuery( "
			INSERT IGNORE INTO activity ( 
				user_id, publisher_id, author_id,
				pub_type, message_id, message
			)
			VALUES ( %l, %l, %l, %l, %e, %e )",
			$this->USER['USER_ID'],
			$this->USER['RELATIONSHIP_ID'],
			$BROWSER['RELATIONSHIP_ID'],
			PUB_TYPE_REMOTE_POST,
			$publicationId,
			$text
		);

		$identity = $BROWSER['IDURL'];
		$hash = $_SESSION['hash'];
		$token = $_SESSION['token'];

		$message = new Message;
		$message->boardPost( $publicationId, $text );

		$connection = new Connection;
		$connection->openLocal();

		$connection->remoteBroadcastRequest( $token, $message->message );

		if ( !$connection->success ) 
			$this->userError( $connection->result, "" );
		$reqid = $connection->regs[1];

		$arg_dsnp   = 'dsnp=remote_broadcast_response';
		$arg_reqid  = 'dsnp_reqid=' . urlencode( $reqid );
		$arg_backto = 'dsnp_backto=' . urlencode( $this->USER['IDURL'] );
		
		$dest = addArgs( $identity, "{$arg_dsnp}&{$arg_reqid}&{$arg_backto}" );
			
		$this->redirect( $dest );
	}

	function finish()
	{
		$reqid = $this->args['dsnp_reqid'];

		$connection = new Connection;
		$connection->openLocal();
		$connection->remoteBroadcastFinal( $_SESSION['token'], $reqid );
		$this->userRedirect( "/" );
	}
};
