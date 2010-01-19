<?php
class FriendsController extends AppController
{
	var $name = 'Friends';
	var $helpers = array("html", "text");
	var $uses = array();

	function beforeFilter()
	{
		$this->checkUserMaybeActivateSession();
	}

	function findFriendsWithNetworkMembers()
	{
		# Load the friend list.
		$this->loadModel( 'FriendClaim' );

		/* LInk to the group member and get the next level (friend_group). */
		$this->FriendClaim->bindModel( array(
			'hasMany' => array( 'NetworkMember' => array( 
				'foreignKey' => 'friend_claim_id' ))
		));
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

	function findNetworks()
	{
		$this->loadModel( 'Network' );
		$networks = $this->Network->find( 'all', array( 
			'conditions' => array( 'user_id' => $this->USER_ID ),
			'order' => 'NetworkName.id' 
		));
		return $networks;
	}

	function manage()
	{
		$this->requireOwner();

		$friendClaims = $this->findFriendsWithNetworkMembers();
		$this->set( 'friendClaims', $friendClaims );

		$networks = $this->findNetworks();
		$this->set( 'networks', $networks );
	}

	function isMember( $networkId, $groupMembers )
	{
		foreach ( $groupMembers as $member ) {
			if ( $networkId == $member['network_id'] )
				return true;
		}
		return false;
	}

	function addToNetwork( $networkName, $claim )
	{
		$identity = $claim['FriendClaim']['identity'];
		$nn = $networkName['NetworkName']['name'];

		#echo "adding $identity to $nn\n";
		#return;

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"add_to_network $this->USER_NAME $nn $identity\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK", $res) )
			die( "FAILURE *** add to network failed with <br> $res" );

		fclose( $fp );
	}

	function removeFromNetwork( $networkName, $claim )
	{
		$identity = $claim['FriendClaim']['identity'];
		$nn = $networkName['NetworkName']['name'];
		
		#echo "removing $identity from $nn\n";
		#return;

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"remove_from_network $this->USER_NAME $nn $identity\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK", $res) )
			die( "FAILURE *** remove from network with <br> $res" );

		fclose( $fp );
	}

	function smanage()
	{
		#echo '<pre>'; 
		#print_r( $this->data ); 

		$friendClaims = $this->findFriendsWithNetworkMembers();
		$networks = $this->findNetworks();

		foreach ( $friendClaims as $claim ) {
			foreach ( $networks as $network ) {
				$checkboxName = 'v_' . $network['Network']['id'] . '_' . $claim['FriendClaim']['id'];
				if ( isset( $this->data['Membership'][$checkboxName] ) ) {
					/* Curent membership status. */
					$currentlyMember = false;
					if ( $this->isMember( $network['Network']['id'], $claim['NetworkMember'] ) )
						$currentlyMember = true;

					/* New membership status. */
					$newMemberStatus = $this->data['Membership'][$checkboxName] != 0;

					/* Add or remove? */
					if ( !$currentlyMember && $newMemberStatus )
						$this->addToNetwork( $network, $claim );
					if ( $currentlyMember && !$newMemberStatus )
						$this->removeFromNetwork( $network, $claim );
				}
			}
		}

		#echo '</pre>';
		#exit;
		$this->redirect( "/$this->USER_NAME/friends/manage/" );
	}

	function addnet()
	{
		$this->requireOwner();
		$networks = $this->findNetworks();
		$this->set( 'networks', $networks );

		$this->loadModel( 'NetworkName' );
		$networkNames = $this->NetworkName->find( 'all', array( 
			'order' => 'NetworkName.id' 
		));
		$this->set( 'networkNames', $networkNames );
	}

	function showNetwork( $networkName )
	{
		$nn = $networkName['NetworkName']['name'];

		$fp = fsockopen( 'localhost', $this->CFG_PORT );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 $this->CFG_URI\r\n" . 
			"comm_key $this->CFG_COMM_KEY\r\n" .
			"show_network $this->USER_NAME $nn\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK", $res) ) die( "FAILURE *** network naame show failed with <br> $res" );

		fclose( $fp );
	}

	function unshowNetwork( $networkName )
	{

	}

	function saddnet()
	{
		$this->requireOwner();
		$networks = $this->findNetworks();

		$this->loadModel( 'NetworkName' );
		$networkNames = $this->NetworkName->find( 'all', array( 
			'order' => 'NetworkName.id' 
		));

		echo "<pre>";
		print_r( $this->data['NetworkUsage'] );
		echo "</pre>";

		foreach ( $networkNames as $nn ) {
			$currentStatus = false;
			foreach ( $networks as $net ) {
				if ( isset( $net['NetworkName']['name'] ) && 
						$net['NetworkName']['id'] == $nn['NetworkName']['id'] )
				{
					$currentStatus = true;
					break;
				}
			}

			$checkboxName = 'v' . $nn['NetworkName']['id'];
			if ( isset( $this->data['NetworkUsage'][$checkboxName] ) ) {
				$newStatus = $this->data['NetworkUsage'][$checkboxName] != 0;

				/* Add or remove? */
				if ( !$currentStatus && $newStatus )
					$this->showNetwork( $nn );
				if ( $currentStatus && !$newStatus )
					$this->unshowNetwork( $nn );
			}
		}

		exit();
		$this->redirect( "/$this->USER_NAME/friends/manage/" );
	}
}
?>
