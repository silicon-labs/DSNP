<?php
class OwnerFreqController extends Controller
{
	var $function = array(
		'answer' => array(),

		'retrelid' => array(
			array( get => 'identity', type => 'identity' ),
			array( get => 'fr_reqid', type => 'base64' ),
		),
	);

	function retrelid()
	{
		$identity = $this->args['identity'];
		$fr_reqid = $this->args['fr_reqid'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->relidResponse( 
			$this->USER[USER], $fr_reqid, $identity );

		$arg_identity = 'identity=' . urlencode( $this->USER['iduri']);
		$arg_reqid = 'reqid=' . urlencode( $connection->regs[1] );

		$this->redirect("${identity}freq/frfinal?${arg_identity}&${arg_reqid}" );
	}

	function answer()
	{
		$reqid = $_GET['reqid'];

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->acceptFriend( 
			$this->USER[USER], $reqid );

		if ( !$connection->success ) {
			$this->userError( "FAILURE *** Friend accept " .
				"failed with: <br>" . $connection->result, "" );
		}

		$this->userRedirect( "/" );
	}
}
?>
