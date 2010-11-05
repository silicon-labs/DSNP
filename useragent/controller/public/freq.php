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
			$this->error(
				'The identity submitted belongs to this user.',
				'It is not possible to friend request oneself.'
			);
		}

		$connection = new Connection;
		$connection->openLocalPriv();

		$connection->relidRequest( $this->USER[USER], $identity );

		if ( ereg("^OK ([-A-Za-z0-9_]+)",
				$connection->result, $regs ) )
		{
			$arg_identity = 'identity=' . urlencode( $this->USER[URI]);
			$arg_reqid = 'fr_reqid=' . urlencode( $regs[1] );

			$this->redirect("{$identity}freq/retrelid?{$arg_identity}&{$arg_reqid}" );
		}
		else if ( ereg("^ERROR ([0-9]+)", $connection->result, $regs) ) {
			$this->error(
				'The DSNP server responded with an error.',
				'The server responded with error code ' . $regs[1] . '. ' .
				'Check that the URI you submitted is correct. ' .
				'If the problem persists contact the system administrator.'
			);
		}
		else {
			$this->error(
				'The DSNP server did not responsd.',
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

		if ( ereg("^OK", $connection->result ) ) {
			$this->redirect( $this->USER[URI] );
		}
		else {
			echo $this->result;
		}
	}
}
?>
