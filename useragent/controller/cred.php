<?php

class CredController extends Controller
{
	function submitFriendLogin( $hash )
	{
		/* This login routine is used by a diferent cred controllers. */
		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->ftokenRequest( $this->USER['USER'], $hash );

		$arg_h = 'h=' . urlencode( $connection->hash );
		$arg_reqid = 'reqid=' . urlencode( $connection->reqid );
		$dest = "";

		# FIXME: put this into the args definition.
		if ( isset( $_GET['d'] ) )
			$dest = "&d=" . urlencode($_GET['d']);
			
		$this->redirect(
			"{$connection->iduri}cred/retftok?{$arg_h}&{$arg_reqid}{$dest}" );
	}

	function destroySession()
	{
		session_destroy();
		setcookie('PHPSESSID', '', time() - 3600, '/');
	}
}
?>
