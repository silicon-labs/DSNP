<?php
class FriendsController extends AppController
{
	var $name = 'Friends';
	var $helpers = array("html", "text");
	var $uses = array();

	function beforeFilter()
	{
		$this->checkUser();
		$this->maybeActivateSession();
		$this->checkRole();
	}

	function findFriendsWithGroups()
	{
		# Load the friend list.
		$this->loadModel( 'FriendClaim' );

		/* LInk to the group member and get the next level (friend_group). */
		$this->FriendClaim->bindModel( array(
			'hasMany' => array( 'GroupMember' => array( 
				'foreignKey' => 'friend_claim_id' 
		) ) ) );
		$this->FriendClaim->recursive = 2;

		$friendClaims = $this->FriendClaim->find('all', 
				array( 'conditions' => array( 'user_id' => $this->USER_ID )));
		return $friendClaims;
	}

	function findGroups()
	{
		/* Get the list of groups so we known how many columns to make. */
		$this->loadModel( 'FriendGroup' );
		$friendGroups = $this->FriendGroup->find('all', array( 
			'conditions' => array( 'user_id' => $this->USER_ID ),
			'order' => 'id'
		));
		return $friendGroups;
	}

	function manage()
	{
		$this->requireOwner();

		$friendClaims = $this->findFriendsWithGroups();
		$this->set( 'friendClaims', $friendClaims );

		$friendGroups = $this->findGroups();
		$this->set( 'friendGroups', $friendGroups );

	}

	function isMember( $groupMembers, $groupId )
	{
		foreach ( $groupMembers as $member ) {
			if ( $groupId == $member['friend_group_id'] )
				return true;
		}
		return false;
	}

	function addToGroup( $group, $claim )
	{
		$identity = $claim['FriendClaim']['identity'];
		$gname = $group['FriendGroup']['name'];

		#echo "$identity to $gname\n";
		#return;

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"add_to_group $this->USER_NAME $gname $identity\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK", $res) )
			die( "FAILURE *** group add failed with <br> $res" );

		fclose( $fp );

		$this->GroupMember->create();
		$this->GroupMember->save( array( 
				'friend_group_id' => $group['FriendGroup']['id'],
				'friend_claim_id' => $claim['FriendClaim']['id']
		));
	}

	function removeFromGroup( $group, $claim )
	{
		$identity = $claim['FriendClaim']['identity'];
		$gname = $group['FriendGroup']['name'];
		#
		#echo "$identity from $gname\n";
		#
		#$gid = $group['FriendGroup']['id'];
		#$cid = $claim['FriendClaim']['id'];
		#
		#$gmid = $groupMember['GroupMember']['id'];
		#echo "$gid $cid $gmid\n";
		#return;

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"remove_from_group $this->USER_NAME $gname $identity\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK", $res) )
			die( "FAILURE *** group add failed with <br> $res" );

		fclose( $fp );

		$groupMember = $this->GroupMember->find( 'first', array( 
				'conditions' => array (
					'friend_group_id' => $group['FriendGroup']['id'],
					'friend_claim_id' => $claim['FriendClaim']['id']
				)
			));
		$this->GroupMember->delete( $groupMember['GroupMember']['id'] );
	}

	function smanage()
	{
		#echo '<pre>'; 
		#print_r( $this->data ); 

		$friendClaims = $this->findFriendsWithGroups();
		$friendGroups = $this->findGroups();
		$this->loadModel('GroupMember');

		foreach ( $friendClaims as $claim ) {
			foreach ( $friendGroups as $group ) {
				$current = false;
				if ( $this->isMember( $claim['GroupMember'], $group['FriendGroup']['id'] ) )
					$current = true;

				$checkboxName = 'v_' . $group['FriendGroup']['id'] . '_' . $claim['FriendClaim']['id'];
				if ( isset( $this->data['Membership'][$checkboxName] ) ) {
					$new = $this->data['Membership'][$checkboxName] != 0;
					if ( !$current && $new )
						$this->addToGroup( $group, $claim );
					if ( $current && !$new )
						$this->removeFromGroup( $group, $claim );
				}
			}
		}

		#echo '</pre>';
		#exit;
		$this->redirect( "/$this->USER_NAME/friends/manage/" );
	}

	function addgroup()
	{
		$this->requireOwner();

		/* Get the list of groups so we known how many columns to make. */
		$this->loadModel( 'FriendGroup' );
		$friendGroups = $this->FriendGroup->find('all', array( 
			'conditions' => array( 'user_id' => $this->USER_ID ),
			'order' => 'id'
		));
		$this->set( 'friendGroups', $friendGroups );
	}

	function saddgroup()
	{
		$name = $this->data['FriendGroup']['name'];

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"add_group $this->USER_NAME $name\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK", $res) )
			die( "FAILURE *** group creation failed with <br> $res" );
   	
		$this->loadModel('FriendGroup');
		$this->FriendGroup->save( array( 
				'user_id' => $this->USER_ID,
				'name' => $name
		));

		$this->redirect( "/$this->USER_NAME/friends/manage/" );
	}

}
?>
