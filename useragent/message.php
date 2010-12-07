<?php
class Message
{
	# Outgoing message.
	var $message;

	# Incoming message envelope.
	var $deliveryType;
	var $user;
	var $subject;
	var $author;
	var $seqNum;
	var $date;
	var $time;
	var $length;

	# Incoming message header fields.
	var $type;
	var $contentType;

	function findFriendClaimId( $user, $identity )
	{
		$result = dbQuery(
			"SELECT friend_claim.id FROM friend_claim " .
			"JOIN user ON user.id = friend_claim.user_id " .
			"WHERE user.user = %e AND friend_claim.friend_id = %e",
			$user,
			$identity
		);

		if ( count( $result ) == 1 )
			return (int) $result[0]['id'];
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


	function nameChange( $newName )
	{
		/* User message */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: name-change\r\n" .
			"\r\n";

		$this->message = $headers . $newName;
	}

	function recvNameChange( $forUser, $author_id, $seqNum, 
			$date, $time, $msg, $contextType )
	{
		if ( $contextType != 'text/plain' )
			return;

		$result = dbQuery( "SELECT id FROM user WHERE user = %e", $forUser );

		if ( count( $result ) === 1 ) {
			$user = $result[0];
			dbQuery( 
				"UPDATE friend_claim SET name = %e " . 
				"WHERE user_id = %L AND friend_id = %e",
				$msg[1], $user['id'], $author_id );
		}
	}

	function photoUpload( $id, $fileName )
	{
		$headers = 
			"Content-Type: image/jpg\r\n" .
			"Resource-Id: $id\r\n" .
			"Type: photo-upload\r\n" .
			"\r\n";

		$MAX_BRD_PHOTO_SIZE = 16384;
		$file = fopen( $fileName, "rb" );
		$data = fread( $file, $MAX_BRD_PHOTO_SIZE );
		fclose( $file );

		$this->message = $headers . $data;
	}

	function recvPhotoUpload( $forUser, $author, $seqNum,
			$date, $time, $msg, $contextType )
	{
		global $DATA_DIR;

		/* Need a resource id. */
		if ( !isset( $msg[0]['resource-id'] ) )
			return;

		$local_resid = $seqNum;
		$remote_resid = (int) $msg[0]['resource-id'];

		$user_id = $this->findUserId( $forUser );
		$author_id = $this->findFriendClaimId( $forUser, $author );

		/* The message body is photo data. Write the photo to disk. */
		$path = sprintf( "%s/%s/pub-%ld.jpg", $DATA_DIR, $forUser, $seqNum );

		$length = strlen( $msg[1] );
		$f = fopen( $path, "wb" );
		fwrite( $f, $msg[1], $length );
		fclose( $f );

		$name = sprintf( "pub-%ld.jpg", $seqNum );

		dbQuery(
			"INSERT INTO activity " .
			"	( user_id, author_id, seq_num, time_published, " . 
			"		time_received, type, local_resid, remote_resid, message ) " .
			"VALUES ( %l, %l, %l, %e, now(), %e, %l, %l, %e )",
			$user_id,
			$author_id, 
			$seqNum, 
			$date . ' ' . $time,
			'PHT',
			$local_resid, 
			$remote_resid, 
			$name
		);
	}
	
	function broadcast( $text )
	{
		/* User message */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: broadcast\r\n" .
			"\r\n";

		$this->message = $headers . $text;
	}

	function recvBroadcast( $forUser, $author, $seqNum,
			$date, $time, $msg, $contextType )
	{
		/* Need a resource id. */
		if ( $contextType != 'text/plain' )
			return;

		$userId = $this->findUserId( $forUser );
		$authorId = $this->findFriendClaimId( $forUser, $author );

		print "broadcast $userId $authorId\n";

		dbQuery(
			"INSERT INTO activity " .
			"	( user_id, author_id, seq_num, time_published, " . 
			"		time_received, type, message ) " .
			"VALUES ( %l, %l, %l, %e, now(), %e, %e )",
			$userId, $authorId,
			$seqNum, $date . ' ' . $time,
			'MSG', $msg[1]
		);
	}


	function boardPost( $text )
	{
		/* User message. */
		$headers = 
			"Content-Type: text/plain\r\n" .
			"Type: board-post\r\n" .
			"\r\n";

		$this->message = $headers . $text;
	}

	function recvBoardPost( $forUser, $network, $subject, $author,
			$seqNum, $date, $time, $msg, $contextType )
	{
		$user_id = $this->findUserId( $forUser );
		$subject_id = $this->findFriendClaimId( $forUser, $subject );
		$author_id = $this->findFriendClaimId( $forUser, $author );

		printf("boardPost( $forUser, $network, $subject, " .
				"$author, $seqNum, $date, $time, $msg, $contextType )\n" );

		dbQuery(
			"INSERT INTO activity " .
			"	( " .
			"		user_id, subject_id, author_id, seq_num, time_published, " .
			"		time_received, type, message " .
			"	) " .
			"VALUES ( %l, %l, %l, %l, %e, now(), %e, %e )",
			$user_id,
			$subject_id, 
			$author_id, 
			$seqNum, 
			$date . ' ' . $time,
			'BRD',
			$msg[1]
		);
	}


	function recvRemoteBoardPost( $user, $network, $subject, $msg, $contextType )
	{
		printf( "function remoteBoardPost( $user, $network, " .
				"$subject, $msg, $contextType )\n" );

		$user_id = $this->findUserId( $user );
		$subject_id = $this->findFriendClaimId( $user, $subject );

		dbQuery(
			"INSERT INTO activity " .
			"	( user_id, subject_id, published, time_published, type, message ) " .
			"VALUES ( %l, %l, true, now(), %e, %e )",
			$user_id,
			$subject_id, 
			'BRD',
			$msg[1]
		);
	}


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
			$replaced = preg_replace( '/Content-Type:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['content-type'] = trim($replaced);

			$replaced = preg_replace( '/Resource-Id:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['resource-id'] = trim($replaced);

			$replaced = preg_replace( '/Type:[\t ]*/i', '', $line );
			if ( $replaced !== $line )
				$headers['type'] = trim($replaced);

			if ( $left <= 0 )
				break;
		}
		$msg = fread( $file, $left );
		return array( $headers, $msg );
	}

	function parseBroadcast( $argv, $file )
	{
		# Collect the args.
		$deliveryType = "broadcast";
		$user = $argv[0];
		$author = $argv[1];
		$seqNum = $argv[2];
		$date = $argv[3];
		$time = $argv[4];
		$length = $argv[5];

		$msg = $this->parse( $file, $length );

		if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
			$type = $msg[0]['type'];
			$contextType = $msg[0]['content-type'];
			print("type: $type\n" );
			print("content-type: $contextType\n" );

			switch ( $type ) {
				case 'name-change':
					$this->recvNameChange( $user, $author, $seqNum, 
							$date, $time, $msg, $contextType );
					break;
				case 'photo-upload':
					$this->recvPhotoUpload( $user, $author, $seqNum,
							$date, $time, $msg, $contextType );
					break;
				case 'broadcast':
					$this->recvBroadcast( $user, $author, $seqNum,
							$date, $time, $msg, $contextType );
					break;
			}
		}
	}

	function parseMessage( $argv, $file )
	{
		# Collect the args.
		$deliveryType = "message";
		$user = $argv[0];
		$author = $argv[1];
		$date = $argv[2];
		$time = $argv[3];
		$length = $argv[4];

		# Read the message from stdin.
		$msg = $this->parse( $file, $length );

		if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
			$type = $msg[0]['type'];
			$contextType = $msg[0]['content-type'];
			print("type: $type\n" );
			print("content-type: $contextType\n" );

			switch ( $type ) {
				default:
					break;
			}
		}
	}

	function parseRemoteMessage( $argv, $file )
	{
		# Collect the args.
		$deliveryType = "remote_message";
		$user = $argv[0];
		$subject = $argv[1];
		$author = $argv[2];
		$seqNum = $argv[3];
		$date = $argv[4];
		$time = $argv[5];
		$length = $argv[6];

		# Read the message from stdin.
		$msg = $this->parse( $file, $length );

		if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
			$type = $msg[0]['type'];
			$contextType = $msg[0]['content-type'];
			print("type: $type\n" );
			print("content-type: $contextType\n" );

			switch ( $type ) {
				case 'board-post':
					$this->recvBoardPost( $user, $network, $subject, $author, 
							$seqNum, $date, $time, $msg, $contextType );
					break;
			}
		}
	}

	function parseRemotePublication( $argv, $file )
	{
		# Collect the args.
		$deliveryType = "remote_publication";
		$user = $argv[0];
		$subject = $argv[1];
		$length = $argv[2];

		# Read the message from stdin.
		$msg = $this->parse( $file, $length );

		if ( isset( $msg[0]['type'] ) && isset( $msg[0]['content-type'] ) ) {
			$type = $msg[0]['type'];
			$contextType = $msg[0]['content-type'];
			print("type: $type\n" );
			print("content-type: $contextType\n" );

			switch ( $type ) {
				case 'board-post':
					$this->recvRemoteBoardPost( $user, $network, $subject, 
							$msg, $contextType );
					break;
			}
		}
	}
};
?>
