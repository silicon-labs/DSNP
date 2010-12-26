<?php
class PublicFreqController extends Controller
{
	var $function = array(
		'become' => array(),

		'sbecome' => array(
			array( post => 'identity' ),
			# The recaptcha fields are optional if not using reCAPTCHA.
			array( post => 'recaptcha_challenge_field',
					optional => RECAPTCHA_ARGS_OPTIONAL ),
			array( post => 'recaptcha_response_field', 
					optional => RECAPTCHA_ARGS_OPTIONAL ),
		),

		'frfinal' => array(),

		/* Need to be logged in for this. Prompt for for login and then
		 * redirect. */
		'retrelid' => array(
			array( get => 'identity', type => 'identity' ),
			array( get => 'fr_reqid', type => 'base64' ),
		),
	);

	function become()
	{
	}

	function sbecome()
	{
		$identity = $this->args['identity'];

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

		$arg_identity = 'identity=' . urlencode( $this->USER[URI]);
		$arg_reqid = 'fr_reqid=' . urlencode( $connection->regs[1] );
		$this->redirect("{$identity}freq/retrelid?{$arg_identity}&{$arg_reqid}" );
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

	function retrelid()
	{
		# FIXME: need to give a more helpful message here.
		$this->userRedirect( "/cred/login?d=" . urlencode($_SERVER['REQUEST_URI']) );
	}
}
?>
