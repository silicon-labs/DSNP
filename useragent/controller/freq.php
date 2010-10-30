<?php
class FreqController extends Controller
{
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

#		$fp = fsockopen( 'localhost', $this->CFG_PORT );
#		if ( !$fp )
#			die( "!!! There was a problem connecting to the local SPP server.");
#		
#		$send = 
#			"SPP/0.1 $this->CFG_URI\r\n" . 
#			"comm_key $this->CFG_COMM_KEY\r\n" .
#			"relid_request $this->USER_NAME $identity\r\n";
#		fwrite($fp, $send);
#		
#		$res = fgets($fp);
#
#		if ( ereg("^OK ([-A-Za-z0-9_]+)", $res, $regs) ) {
#			$arg_identity = 'identity=' . urlencode( $this->USER_URI );
#			$arg_reqid = 'fr_reqid=' . urlencode( $regs[1] );
#
#			header("Location: ${identity}freq/retrelid?${arg_identity}&${arg_reqid}" );
#		}
#		else if ( ereg("^ERROR ([0-9]+)", $res, $regs) ) {
#			$this->userError('generic', array(
#				'message' => 'The DSNP server responded with an error.',
#				'details' => 'The server responded with error code ' . $regs[1] . '. ' .
#					'Check that the URI you submitted is correct. ' .
#					'If the problem persists contact the system administrator.'
#			));
#		}
#		else {
#			$this->userError('generic', array(
#				'message' => 'The DSNP server did not responsd.',
#				'details' => 'Check that the URI you submitted is correct. ' .
#					'If the problem persists contact the system administrator.'
#			));
#		}
	}
}
?>
