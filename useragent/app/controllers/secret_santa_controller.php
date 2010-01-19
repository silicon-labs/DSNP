<?php
class SecretSantaController extends AppController
{
	var $name = 'User';
	var $helpers = array("html", "text");

	function beforeFilter()
	{
		$this->checkUserMaybeActivateSession();
	}

	function ssOwner()
	{
		# Load the user's sent friend requests
		$this->loadModel('SentFriendRequest');
		$sentFriendRequests = $this->SentFriendRequest->find('all', 
				array( 'conditions' => array( 'from_user' => $this->USER_NAME )));
		$this->set( 'sentFriendRequests', $sentFriendRequests );

		# Load the user's friend requests. 
		$this->loadModel('FriendRequest');
		$friendRequests = $this->FriendRequest->find( 'all',
				array( 'conditions' => array( 'for_user' => $this->USER_NAME )));
		$this->set( 'friendRequests', $friendRequests );

		# Load the friend list.
		$this->loadModel( 'FriendClaim' );
		$friendClaims = $this->FriendClaim->find('all', 
				array( 'conditions' => array( 'user_id' => $this->USER_ID )));
		$this->set( 'friendClaims', $friendClaims );

		# Load the user's images.
		$this->loadModel('Image');
		$images = $this->Image->find('all', array(
			'conditions' => 
				array( 'user' => $this->USER_NAME ),
			'order' => array( 'Image.seq_num DESC' ),
			'limit' => 30
		));
		$this->set( 'images', $images );

		$this->loadModel('Activity');
		$activity = $this->Activity->find( 'all', array( 
				'conditions' => array( 
					'Activity.user_id' => $this->USER_ID
				),
				'order' => 'time_published DESC',
				'limit' => 30
			));
		$this->set( 'activity', $activity );

		$this->render( 'ss_owner' );
	}

	function ssFriend()
	{
		# Load the friend list.
		$this->loadModel( 'FriendClaim' );
		$friendClaims = $this->FriendClaim->find('all', 
				array( 'conditions' => array( 'user_id' => $this->USER_ID )));
		$this->set( 'friendClaims', $friendClaims );

		# Load the user's images.
		$this->loadModel('Image');
		$images = $this->Image->find('all', array( 
			'conditions' => 
				array( 'user' => $this->USER_NAME ),
			'order' => array( 'Image.seq_num DESC' ),
			'limit' => 30
		));
		$this->set( 'images', $images );

		$this->loadModel('Activity');
		$activity = $this->Activity->find( 'all', array( 
				'conditions' => array( 
					'Activity.user_id' => $this->USER_ID,
					'published' => 'true'
				),
				'order' => 'time_published DESC',
				'limit' => 30
			));
		$this->set( 'activity', $activity );

		$this->loadModel('SecretSanta');
		$givesTo = $this->SecretSanta->find('first', array( 
			'conditions' => 
				array( 'friend_id' => $BROWSER['id'] )
		));
		$givesTo = $this->FriendClaim->find('first', array( 
			'conditions' => 
				array( 'id' => $givesTo['SecretSanta']['gives_to_id'] )
		));
		$this->set( 'givesTo', $givesTo );

		$this->render( 'ss_friend' );
	}

	function ssPublic()
	{
		$this->set( 'ROLE', 'public' );
		$this->render( 'ss_public' );
	}
}
?>
