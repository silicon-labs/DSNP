<?php

require( ROOT . DS . 'controller/image.php' );

class FriendImageController extends ImageController
{
	var $function = array(
		'view' => array(
			array(
				'route' => 'file',
				'N' => 2,
				'regex' => '/^(img|thm|pub)-[0-9]+\.jpg$/'
			)
		),
		'display' => array(
			array(
				'route' => 'file',
				'N' => 2,
				'regex' => '/^(img|thm|pub)-[0-9]+\.jpg$/'
			)
		),
		'stream' => array(),
		'tag' => array(
			array(
				'get' => 'id',
				'type' => 'int'
			),
			array(
				'get' => 'subject',
				'type' => 'iduri'
			),
		),
	);

	function view()
	{
		$file = $this->args['file'];
		$this->viewImage( $file );
	}

	function display()
	{
		$file = $this->args['file'];
		$this->vars['file'] = $file;

		$this->vars['id'] = preg_replace( 
				'/^[a-z]+-([0-9])\.jpg$/', '\1', $file );

		# Load the friend list.
		$friendClaims = dbQuery(
			"SELECT identity.*, relationship.* " .
			"FROM friend_claim " .
			"JOIN identity ON friend_claim.identity_id = identity.id " .
			"JOIN relationship ON friend_claim.relationship_id = relationship.id " .
			"WHERE friend_claim.user_id = %L AND relationship.id != %L",
			$this->USER['USER_ID'], $this->BROWSER['RELATIONSHIP_ID'] );

		$this->vars['friendClaims'] = $friendClaims;
	}

	function stream()
	{
		$start = $this->args[start];

		# Load the user's images.
		$images = dbQuery( "
			SELECT * FROM image WHERE user_id = %L 
			ORDER BY seq_num DESC LIMIT 30",
			$this->USER['USER_ID'] );
		$this->vars['images'] = $images;
	}

	function tag()
	{
		$BROWSER = $_SESSION['BROWSER'];
		$subject = $this->args['subject'];

		/* FIXME: verify against database (someone else's id) */
		$imageId = $this->args['id'];

		dbQuery( "
			INSERT INTO publication ( user_id, author_id )
			VALUES ( %l, %l )", 
			$this->USER['USER_ID'], 
			$this->USER['RELATIONSHIP_ID']
		);
		$publicationId = lastInsertId();

		$subjectIdentityId = findIdentityId( $subject );
		$subjectRshipId = findRelationshipId( $this->USER['USER_ID'], $subjectIdentityId );

		$identity = $BROWSER['IDURL'];
		$hash = $_SESSION['hash'];
		$token = $_SESSION['token'];

		# Where the user's photos go.
		$dir = $this->imageDir();
		$thumb = "$dir/thm-$imageId.jpg";

		$remoteResource      = $this->userLoc( "/image/view/img-$imageId.jpg" );
		$remotePresentation  = $this->userLoc( "/image/display/img-$imageId.jpg" );

		$localThumbnail      = "/image/view/thm-$imageId.jpg";
		$localResource       = "/image/view/img-$imageId.jpg";
		$localPresentation   = "/image/display/img-$imageId.jpg";

		dbQuery( "
			INSERT IGNORE INTO activity (
				user_id, publisher_id, author_id,
				subject_id, pub_type, message_id,
				local_thumbnail, local_resource, local_presentation
			)
			VALUES ( %l, %l, %l, %l, %l, %e, %e, %e, %e )",
			$this->USER['USER_ID'],
			$this->USER['RELATIONSHIP_ID'],
			$BROWSER['RELATIONSHIP_ID'],
			$subjectRshipId,
			PUB_TYPE_PHOTO_TAG,
			$publicationId,
			$localThumbnail, 
			$localResource, 
			$localPresentation
		);
			
		$message = new Message;
		$message->photoTag( $publicationId, $subject,
				$remoteResource, $remotePresentation,
				$imageId, $thumb );

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
}
?>
