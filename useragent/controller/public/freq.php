<?php
class PublicFreqController extends Controller
{
	var $function = array(
		'submit' => array(),
		'sbecome' => array(),
		'frfinal' => array(),
	);

	function submit()
	{
	}

	function sbecome()
	{
		global $USER;
		$identity = $_POST['identity'];

		if ( $identity === $this->USER[URI] ) {
			$this->userError(
				'The identity submitted belongs to this user.',
				'It is not possible to friend request oneself.'
			);
		}

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->relidRequest( $this->USER[USER], $identity );

		if ( $connection->success ) {
			$arg_identity = 'identity=' . urlencode( $this->USER[URI]);
			$arg_reqid = 'fr_reqid=' . urlencode( $connection->regs[1] );

			$this->redirect("{$identity}freq/retrelid?{$arg_identity}&{$arg_reqid}" );
		}
		else {
			$this->userError(
				'The DSNP server responded with an error.',
				'The server responded with error code ' . $connection->regs[1] . '. ' .
				'Check that the URI you submitted is correct. ' .
				'If the problem persists contact the system administrator.'
			);
		}
	}

	function frfinal()
	{
		$identity = $_GET['identity'];
		$reqid = $_GET['reqid'];

		$connection = new Connection;
		$connection->openLocalPriv();
		$connection->frFinal( $this->USER[USER], $reqid, $identity );

		if ( $connection->success ) {
			$this->redirect( $this->USER[URI] );
		}
		else {
			echo $this->result;
		}
	}
}
?>
