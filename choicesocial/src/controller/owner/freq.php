<?php
class OwnerFreqController extends Controller
{
	var $function = array(
		'answer' => array(
			array( get => 'reqid', type => 'base64' ),
		),

		'retrelid' => array(
			array( get => 'dsnp_iduri', type => 'iduri' ),
			array( get => 'dsnp_reqid', type => 'base64' ),
		),
	);

	function retrelid()
	{
		$iduri = $this->args['dsnp_iduri'];
		$reqid = $this->args['dsnp_reqid'];

		$connection = new Connection;
		$connection->openLocal();

		$connection->relidResponse( $_SESSION['token'],
				$reqid, $iduri );

		$arg_dsnp   = 'dsnp=friend_final';
		$arg_iduri  = 'dsnp_iduri=' . urlencode( $this->USER['IDURI']);
		$arg_reqid  = 'dsnp_reqid=' . urlencode( $connection->regs[1] );

		$idurl = iduriToIdurl( $iduri );

		$dest = addArgs( $idurl, "{$arg_dsnp}&${arg_iduri}&${arg_reqid}" );

		$this->redirect( $dest );
	}

	function answer()
	{
		$reqid = $this->args['reqid'];

		$connection = new Connection;
		$connection->openLocal();

		$connection->acceptFriend( 
				$_SESSION['token'], $reqid );

		$this->userRedirect( "/" );
	}
}
?>
