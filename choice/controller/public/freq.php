<?php
class PublicFreqController extends Controller
{
	var $function = array(
		'become' => array(),

		'sbecome' => array(
			array( post => 'dsnp_iduri' ),

			# The recaptcha fields are optional if not using reCAPTCHA.
			array( post => 'recaptcha_challenge_field',
					optional => RECAPTCHA_ARGS_OPTIONAL ),
			array( post => 'recaptcha_response_field', 
					optional => RECAPTCHA_ARGS_OPTIONAL ),
		),

		'frfinal' => array(
			array( get => 'dsnp_iduri', type => 'iduri' ),
			array( get => 'dsnp_reqid', type => 'base64' ),
		),

		/* Need to be logged in for this. Catch and do something. */
		'retrelid' => array(
			array( get => 'dsnp_iduri', type => 'iduri' ),
			array( get => 'dsnp_reqid', type => 'base64' ),
		),
	);

	function become()
	{
	}

	function sbecome()
	{
		$iduri = $this->args['dsnp_iduri'];

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
		$connection->openLocal();
		$connection->relidRequest( $this->USER['IDURI'], $iduri );

		$arg_dsnp   = 'dsnp=relid_response';
		$arg_iduri  = 'dsnp_iduri=' . urlencode( $this->USER['IDURI']);
		$arg_reqid  = 'dsnp_reqid=' . urlencode( $connection->regs[1] );

		$idurl = iduriToIdurl( $iduri );
		$dest = addArgs( $idurl, "{$arg_dsnp}&{$arg_iduri}&{$arg_reqid}" );

		$this->redirect( $dest );
	}

	function frfinal()
	{
		$iduri = $this->args['dsnp_iduri'];
		$reqid = $this->args['dsnp_reqid'];

		$connection = new Connection;
		$connection->openLocal();
		$connection->frFinal( $this->USER['IDURI'], $reqid, $iduri );

		$this->redirect( $this->USER['IDURL'] );
	}

	function retrelid()
	{
		userError( EC_MUST_LOGIN, array() );
	}
}
?>
