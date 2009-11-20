<?php
class WishController extends AppController
{
	var $name = 'Wish';

	function beforeFilter()
	{
		$this->checkUser();
		$this->maybeActivateSession();
		$this->checkRole();
	}

	function view( $fc_id )
	{
		$BROWSER = $this->Session->read('BROWSER');
		$this->set( 'BROWSER', $BROWSER );

		$this->data = $this->Wish->find( 'first', array( 
				'conditions' => array( 'FriendClaim.id' => $fc_id )));

		if ( empty( $this->data ) ) {
			$this->loadModel( 'FriendClaim' );
			$this->data = $this->FriendClaim->find( 'first', 
				array( 'conditions' => array( 'FriendClaim.id' => $fc_id )));
		}
	}

	function edit( $fc_id )
	{
		# Make sure that the wish list requested correspons to the signed in
		# friend.
		$BROWSER = $this->Session->read('BROWSER');
		$this->set( 'BROWSER', $BROWSER );

		if ( $fc_id != $BROWSER['id'] ) {
			$this->userError('generic', array(
				'message' => 'not authorized',
				'details' => 'you are not authorized to edit this list'
			));
		}

		$this->data = $this->Wish->find( 'first', array( 
				'conditions' => array( 'friend_claim_id' => $fc_id )));

		if ( empty( $this->data ) ) {
			$this->Wish->save( 
				array( 'friend_claim_id' => $fc_id ));

			$this->data = $this->Wish->find( 'first', array( 
					'conditions' => array( 'friend_claim_id' => $fc_id )));
		}
	}

	function sedit()
	{
		$BROWSER = $this->Session->read('BROWSER');
		$fc_id = $this->data['Wish']['friend_claim_id'];
		if ( $fc_id != $BROWSER['id'] ) {
			$this->userError('generic', array(
				'message' => 'not authorized',
				'details' => 'you are not authorized to edit this list'
			));
		}

		# FIXME: make sure friend_claim_id is us.

		$this->Wish->save( $this->data, true, array('list') );
		$this->redirect( "/$this->USER_NAME/wish/view/$fc_id" );
	}
}
?>
