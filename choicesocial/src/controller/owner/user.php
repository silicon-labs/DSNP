<?php
class OwnerUserController extends Controller
{
	var $function = array(
		'broadcast' => array(
			array(
				post => 'message'
			),
		),
		'flush' => array(
			array( 
				get => 'dsnp_reqid', 
				type => 'base64', 
				length => TOKEN_BASE64_SIZE
			),
			array(
				get => 'dsnp_backto'
			)
		),
		'edit' => array(),
		'sedit' => array(
			array( post => 'name', nonEmpty => 'true' ),
			# Disabled until it can do something useful.
			# array( post => 'email' ),
		),
	);

	function broadcast()
	{
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
				user_id, publisher_id, pub_type,
				message_id, message
			)
			VALUES ( %l, %l, %l, %e, %e )", 
			$this->USER['USER_ID'], 
			$this->USER['RELATIONSHIP_ID'],
			PUB_TYPE_POST,
			$publicationId,
			$text
		);

		$message = new Message;
		$message->broadcast( $publicationId, $text );

		$connection = new Connection;
		$connection->openLocal();
		$connection->submitBroadcast( 
			$_SESSION['token'], $message->message );

		$this->userRedirect( '/' );
	}

	function flush()
	{
		$reqid = $this->args['dsnp_reqid'];
		$backto = $this->args['dsnp_backto'];

		$connection = new Connection;
		$connection->openLocal();

		$connection->remoteBroadcastResponse(
			$_SESSION['token'], $reqid );

		$reqid = $connection->regs[1];

		$arg_dsnp   = 'dsnp=remote_broadcast_final';
		$arg_reqid  = 'dsnp_reqid=' . urlencode( $reqid );
		
		$dest = addArgs( $backto, "{$arg_dsnp}&{$arg_reqid}" );

		$this->redirect( $dest );
	}

	function edit()
	{
		$user = dbQuery( 
			"SELECT * FROM user WHERE user = %e", 
			$this->USER['USER'] );
		$this->vars['user'] = $user;
	}

	function sedit()
	{
		$name = $this->args['name'];
		$email = $this->args['email'];

		if ( preg_match( '/^[ \t\n]*$/', $name ) )
			$name = null;
		if ( preg_match( '/^[ \t\n]*$/', $email ) )
			$email = null;

		dbQuery( 
			"UPDATE relationship SET name = %e, email = %e WHERE id = %l",
			$name, $email, $this->USER['RELATIONSHIP_ID'] );

		/* User Message */
		$message = new Message;
		$message->nameChange( $name );

		$connection = new Connection;
		$connection->openLocal();
		$connection->submitBroadcast( 
				$_SESSION['token'], $message->message );

		$this->userRedirect( "/user/edit" );
	}
}
?>
