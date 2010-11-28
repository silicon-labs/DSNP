<?php

class CredController extends Controller
{
	function submitFriendLogin( $hash )
	{
		/* This login routine is used by a diferent cred controllers. */
		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->ftokenRequest( $this->USER[USER], $hash );

		if ( $connection->success ) {
			$arg_h = 'h=' . urlencode( $connection->regs[3] );
			$arg_reqid = 'reqid=' . urlencode( $connection->regs[1] );
			$friend_id = $connection->regs[2];
			$dest = "";

			# FIXME: put this into the args definition.
			if ( isset( $_GET['d'] ) )
				$dest = "&d=" . urlencode($_GET['d']);
				
			$this->redirect(
				"{$friend_id}cred/retftok?{$arg_h}&{$arg_reqid}{$dest}" );
		}
		else {
			$this->userRedirect( "/" );
		}
	}

	function destroySession()
	{
		session_destroy();
		setcookie('PHPSESSID', '', time() - 3600, '/');
	}
}
?>
