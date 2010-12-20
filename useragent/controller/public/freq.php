<?php
class PublicFreqController extends Controller
{
	var $function = array(
		'submit' => array(),

		'sbecome' => array(
			array( post => 'identity' ),
			# The recaptcha fields are optional if not using reCAPTCHA.
			array( post => 'recaptcha_challenge_field',
					optional => RECAPTCHA_ARGS_OPTIONAL ),
			array( post => 'recaptcha_response_field', 
					optional => RECAPTCHA_ARGS_OPTIONAL ),
		),

		'frfinal' => array(),
	);

	function submit()
	{
	}

	function sbecome()
	{
		$identity = $this->args['identity'];

		if ( $identity === $this->USER[URI] ) {
			$this->userError(
				'The identity submitted belongs to this user.',
				'It is not possible to friend request oneself.'
			);
		}

		if ( $this->CFG['USE_RECAPTCHA'] ) {
			require_once( RECAPTCHA_LIB );

			$resp = recaptcha_check_answer(
					$this->CFG['RC_PRIVATE_KEY'],
					$_SERVER['REMOTE_ADDR'],
					$this->args['recaptcha_challenge_field'],
					$this->args['recaptcha_response_field'] );

			if ( ! $resp->is_valid ) {
				// What happens when the CAPTCHA was entered incorrectly
				die ("The reCAPTCHA wasn't entered correctly. Go back and try it again." .
						"(reCAPTCHA said: " . $resp->error . ")");
			}
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
