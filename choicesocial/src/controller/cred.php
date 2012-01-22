<?php

class CredController extends Controller
{
	function submitFriendLogin( $hash )
	{
		/* This login routine is used by a diferent cred controllers. */
		$connection = new Connection;
		$connection->openLocal();

		$connection->ftokenRequest( $this->USER['IDURI'], $hash );

		/* FIXME: If there is no friend claim ... send back a reqid anyways.
		 * Don't want to give away that there is no claim, otherwise it would
		 * be possible to probe  Would be good to fake this with an appropriate
		 * time delay. */

		$arg_dsnp  = 'dsnp=ftoken_response';
		$arg_hash  = 'dsnp_hash=' . urlencode( $connection->hash );
		$arg_reqid = 'dsnp_reqid=' . urlencode( $connection->reqid );

		$dest = addArgs( iduriToIdurl( $connection->iduri ),
				"{$arg_dsnp}&{$arg_hash}&{$arg_reqid}" );

		if ( isset( $this->args['dest'] ) ) {
			$arg_dest = "dest=" . urlencode( $this->args['dest'] );
			$dest = addArgs( $dest, $arg_dest );
		}
			
		$this->redirect( $dest );
	}

	function destroySession()
	{
		$path = cookiePath();
		$expire = time() - 3600;
		session_destroy();
		setcookie( 'PHPSESSID', '', $expire, $path );
	}
}
?>
