<?php

function findIdentityId( $iduri )
{
	$results = dbQuery(
		"SELECT id FROM identity WHERE iduri = %e",
		$iduri
	);

	if ( count( $results ) == 1 )
		return (int) $results[0]['id'];
	return -1;
}

function findUserId( $user )
{
	$results = dbQuery(
		"SELECT id FROM user WHERE user.user = %e",
		$user
	);

	if ( count( $results ) == 1 )
		return (int) $results[0]['id'];
	return -1;
}

function storeRelationship( $userId, $type, $identityId, $name )
{
	dbQuery( "
		INSERT IGNORE INTO relationship ( 
			user_id, type, identity_id, name
		) 
		VALUES ( %L, %l, %L, %e ) ",
		$userId, $type, $identityId, $name );
}

function findRelationshipId( $userId, $identityId )
{
	$result = dbQuery( "
		SELECT id 
		FROM relationship 
		WHERE user_id = %L AND identity_id = %L",
		$userId,
		$identityId
	);

	if ( count( $result ) == 1 )
		return (int) $result[0]['id'];
	return -1;
}

function nameFromIduri( $iduri )
{
	/* As of version 0.6 of the protocol, an iduri can be any URI as long as
	 * the scheme is dsnp. It is not possible to extract an name from an IDURI. */
	return $iduri;
}

class Message
{
	# Outgoing message.
	var $message;

	# Incoming message envelope.
	var $user;
	var $subject;
	var $author;
	var $date;
	var $time;
	var $length;

	# Incoming message header fields.
	var $type;
	var $contentType;

	#
	# Name Change
	#

	function nameChange( $newName )
	{
		global $USER;

		/* User message */
		$headers = 
			"Publisher-Iduri: " . $USER['IDURI'] . "\r\n" .
			"Type: name-change\r\n" .
			"Message-Id: 55\r\n" .
			"Date: " . $this->curDate() . "\r\n" .
			"Content-Type: text/plain\r\n" .
			"\r\n";

		$this->message = $headers . $newName;
	}

	function recvNameChange( $user, $author, $msg, $contextType )
	{
		if ( $contextType != 'text/plain' )
			return;

		$userId = findUserId( $user );
		$authorId = findIdentityId( $author );
		$authorRshipId = findRelationshipId( $userId, $authorId );
		dbQuery( 
			"UPDATE relationship SET name = %e " . 
			"WHERE id = %L",
			$msg[1], $authorRshipId );
	}

	function curDate()
	{
		return date( 'Y-m-d H:i:s' );
	}


	#
	# Status Update / Broadcast Message
	#
	
	function broadcast( $messageId, $text )
	{
		global $USER;

		/* User message */
		$headers = 
			"Publisher-Iduri: " . $USER['IDURI'] . "\r\n" .
			"Type: broadcast\r\n" .
			"Message-Id: $messageId\r\n" .
			"Date: " . $this->curDate() . "\r\n" .
			"Content-Type: text/plain\r\n" .
			"\r\n";

		$this->message = $headers . $text;
	}

	function recvBroadcast( $user, $publisher,
			$msg, $contextType )
	{
		/* Need a resource id. */
		if ( $contextType != 'text/plain' )
			return;

		$userId = findUserId( $user );
		$publisherId = findIdentityId( $publisher );
		$publisherRshipId = findRelationshipId( $userId, $publisherId );
		$messageId = $msg[0]['message-id'];

		dbQuery( "
			INSERT IGNORE INTO activity
			(
				user_id, publisher_id, time_published,
				time_received, pub_type, message_id, message
			)
			VALUES ( %l, %l, now(), now(), %e, %e, %e )",
			$userId, $publisherRshipId,
			PUB_TYPE_POST, $messageId, $msg[1]
		);
	}

	#
	# Photo Upload
	#

	function photoUpload( $messageId, $remoteResource, $remotePresentation, $id, $fileName )
	{
		global $USER;

		$headers = 
			"Publisher-Iduri: " . $USER['IDURI'] . "\r\n" .
			"Type: photo-upload\r\n" .
			"Message-Id: $messageId\r\n" .
			"Remote-Resource: $remoteResource\r\n" .
			"Remote-Presentation: $remotePresentation\r\n" .
			"Content-Type: image/jpg\r\n" .
			"Date: " . $this->curDate() . "\r\n" .
			"\r\n";

		$MAX_BRD_PHOTO_SIZE = 16384;
		$file = fopen( $fileName, "rb" );
		$data = fread( $file, $MAX_BRD_PHOTO_SIZE );
		fclose( $file );

		$this->message = $headers . $data;
	}

	function recvPhotoUpload( $user, $publisher, $msg, $contextType )
	{
		global $DATA_DIR;

		$userId = findUserId( $user );

		# Make a row in the db ofor the image.
		dbQuery( "
			INSERT INTO remote_image ( user_id )
			VALUES ( %l );",
			$userId
		);

		# Get the id for the row, will use it in the filename.
		$remoteImageId = lastInsertId();

		$remoteResource = $msg[0]['remote-resource'];
		$remotePresentation = $msg[0]['remote-presentation'];
		$messageId = $msg[0]['message-id'];

		# Should be the same as publisher-iduri, otherwise reject.
		$publisherId = findIdentityId( $publisher );
		$publisherRshipId = findRelationshipId( $userId, $publisherId );

		$path = "$DATA_DIR/$user/pub-$remoteImageId.jpg";
		$localThumbnail = "/image/view/pub-$remoteImageId.jpg";

		/* The message body is photo data. Write the photo to disk. */
		$length = strlen( $msg[1] );
		$f = fopen( $path, "wb" );
		fwrite( $f, $msg[1], $length );
		fclose( $f );

		dbQuery( "
			INSERT IGNORE INTO activity
			( 
				user_id, publisher_id, remote_resource, remote_presentation,
				time_published, time_received, pub_type, message_id,
				local_thumbnail
			)
			VALUES ( %l, %l, %e, %e, now(), now(), %l, %e, %e )",
			$userId,
			$publisherRshipId, 
			$remoteResource,
			$remotePresentation,
			PUB_TYPE_PHOTO,
			$messageId,
			$localThumbnail
		);
	}

	#
	# Remote Board Posting.
	#

	function boardPost( $messageId, $text )
	{
		global $USER;
		global $BROWSER;

		/* User message. */
		$headers = 
			"Publisher-Iduri: " . $USER['IDURI'] . "\r\n" .
			"Author-Iduri: " . $BROWSER['IDURI'] . "\r\n" .
			"Type: board-post\r\n" .
			"Message-Id: $messageId\r\n" .
			"Date: " . $this->curDate() . "\r\n" .
			"Content-Type: text/plain\r\n" .
			"\r\n";

		$this->message = $headers . $text;
	}

	function recvBoardPost( $user, $publisher, $author,
			$msg, $contextType )
	{
		$userId = findUserId( $user );
		$messageId = $msg[0]['message-id'];

		$publisherIdentityId = findIdentityId( $publisher );
		$publisherName = nameFromIduri( $publisher );

		$authorIdentityId = findIdentityId( $author );
		$authorName = nameFromIduri( $author );

		# A participant may not be known to us. Note that we alway use
		# REL_TYPE_FRIEND, which is safe because if the identity is the user
		# the relationship will already exist and have REL_TYPE_SELF set. This
		# is done during identity initialization.
		storeRelationship( $userId, REL_TYPE_FRIEND, $publisherIdentityId, $publisherName );
		storeRelationship( $userId, REL_TYPE_FRIEND, $authorIdentityId, $authorName );
	
		$publisherId = findIdentityId( $publisher );
		$publisherRshipId = findRelationshipId( $userId, $publisherId );

		$authorId = findIdentityId( $userId, $author );
		$authorRshipId = findRelationshipId( $userId, $authorId );

		dbQuery( "
			INSERT IGNORE INTO activity
			(
				user_id, publisher_id, author_id,
				time_published, time_received, pub_type, 
				message_id, message
			)
			VALUES ( %l, %l, %l, now(), now(), %l, %e, %e )",
			$userId,
			$publisherRshipId, 
			$authorRshipId, 
			PUB_TYPE_REMOTE_POST,
			$messageId,
			$msg[1]
		);
	}

	function photoTag( $messageId, $subject, $remoteResource, $remotePresentation, $id, $fileName )
	{
		global $USER;
		global $BROWSER;

		/* User message. */
		$headers = 
			"Publisher-Iduri: " . $USER['IDURI'] . "\r\n" .
			"Author-Iduri: " . $BROWSER['IDURI'] . "\r\n" .
			"Subject-Iduri: $subject\r\n" .
			"Type: photo-tag\r\n" .
			"Remote-Resource: $remoteResource\r\n" .
			"Remote-Presentation: $remotePresentation\r\n" .
			"Message-Id: $messageId\r\n" .
			"Date: " . $this->curDate() . "\r\n" .
			"Content-Type: text/plain\r\n" .
			"\r\n";

		# FIXME: function in the upload() as well.
		$MAX_BRD_PHOTO_SIZE = 16384;
		$file = fopen( $fileName, "rb" );
		$data = fread( $file, $MAX_BRD_PHOTO_SIZE );
		fclose( $file );

		$this->message = $headers . $data;
	}

	function recvPhotoTag( $user, $publisher,
			$author, $subject, $msg, $contextType )
	{
		global $DATA_DIR;

		$userId = findUserId( $user );

		# Make a row in the db ofor the image.
		dbQuery( "
			INSERT INTO remote_image ( user_id )
			VALUES ( %l );",
			$userId
		);

		# Get the id for the row, will use it in the filename.
		$remoteImageId = lastInsertId();

		$remoteResource = $msg[0]['remote-resource'];
		$remotePresentation = $msg[0]['remote-presentation'];
		$messageId = $msg[0]['message-id'];

		$publisherIdentityId = findIdentityId( $publisher );
		$publisherName = nameFromIduri( $publisher );

		$authorIdentityId = findIdentityId( $author );
		$authorName = nameFromIduri( $author );

		$subjectIdentityId = findIdentityId( $subject );
		$subjectName = nameFromIduri( $subject );

		# A participant may not be known to us. Note that we alway use
		# REL_TYPE_FRIEND, which is safe because if the identity is the user
		# the relationship will already exist and have REL_TYPE_SELF set. This
		# is done during identity initialization.
		storeRelationship( $userId, REL_TYPE_FRIEND, $publisherIdentityId, $publisherName );
		storeRelationship( $userId, REL_TYPE_FRIEND, $authorIdentityId, $authorName );
		storeRelationship( $userId, REL_TYPE_FRIEND, $subjectIdentityId, $subjectName );

		$publisherRshipId = findRelationshipId( $userId, $publisherIdentityId );
		$authorRshipId = findRelationshipId( $userId, $authorIdentityId );
		$subjectRshipId = findRelationshipId( $userId, $subjectIdentityId );
	
		$path = "$DATA_DIR/$user/pub-$remoteImageId.jpg";
		$localThumbnail = "/image/view/pub-$remoteImageId.jpg";

		/* The message body is photo data. Write the photo to disk. */
		$length = strlen( $msg[1] );
		$f = fopen( $path, "wb" );
		fwrite( $f, $msg[1], $length );
		fclose( $f );

		dbQuery( "
			INSERT IGNORE INTO activity 
			(
				user_id, publisher_id, author_id, subject_id,
				remote_resource, remote_presentation,
				time_published, time_received, pub_type,
				message_id, local_thumbnail
			) 
			VALUES ( %l, %l, %l, %l, %e, %e, now(), now(), %l, %e, %e )",
			$userId,
			$publisherRshipId, 
			$authorRshipId, 
			$subjectRshipId, 
			$remoteResource,
			$remotePresentation,
			PUB_TYPE_PHOTO_TAG,
			$messageId,
			$localThumbnail
		);
	}

	function parseBroadcast( $user, $broadcaster, $length, $file )
	{
		$msg = $this->parse( $file, $length );

		if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
			$publisher = $msg[0]['publisher-iduri'];
			$type = $msg[0]['type'];
			$contextType = $msg[0]['content-type'];

			switch ( $type ) {
				case 'name-change':
					$this->recvNameChange( $user, $publisher,
							$msg, $contextType );
					break;
				case 'photo-upload':
					$this->recvPhotoUpload( $user, $publisher,
							$msg, $contextType );
					break;
				case 'broadcast':
					$this->recvBroadcast( $user, $publisher,
							$msg, $contextType );
					break;
				case 'board-post':
					$author = $msg[0]['author-iduri'];
					$this->recvBoardPost( $user, $publisher, 
							$author, $msg, $contextType );
					break;
				case 'photo-tag':
					$author = $msg[0]['author-iduri'];
					$subject = $msg[0]['subject-iduri'];
					$this->recvPhotoTag( $user, $publisher, 
							$author, $subject, $msg, $contextType );
					break;
			}
		}
	}

	function parseMessage( $use, $sender, $length, $file )
	{
		$msg = $this->parse( $file, $length );

		if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
			$type = $msg[0]['type'];
			$contextType = $msg[0]['content-type'];

			switch ( $type ) {
				default:
					break;
			}
		}
	}

	# Message Parsing
	function parse( $file, $len )
	{
		$headers = array();
		$left = $len;
		while ( true ) {
			$line = fgets( $file );
			if ( $line === "\r\n" ) {
				$left -= 2;
				break;
			}
			$left -= strlen( $line );

			/* Parse headers. */
			$replaced = preg_replace( '/^Content-Type:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['content-type'] = trim($replaced);

			$replaced = preg_replace( '/^Type:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['type'] = trim($replaced);

			$replaced = preg_replace( '/^Date:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['date'] = trim($replaced);

			$replaced = preg_replace( '/^Publisher-Iduri:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['publisher-iduri'] = trim($replaced);

			$replaced = preg_replace( '/^Author-Iduri:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['author-iduri'] = trim($replaced);

			$replaced = preg_replace( '/^Subject-Iduri:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['subject-iduri'] = trim($replaced);

			$replaced = preg_replace( '/^Message-Id:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['message-id'] = trim($replaced);

			$replaced = preg_replace( '/^Remote-Resource:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['remote-resource'] = trim($replaced);

			$replaced = preg_replace( '/^Remote-Presentation:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['remote-presentation'] = trim($replaced);

			if ( $left <= 0 )
				break;
		}
		$msg = $left > 0 ? fread( $file, $left ) : "";
		return array( $headers, $msg );
	}
};

?>
