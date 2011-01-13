<?
class SiteIndexController extends Controller
{
	var $function = array(
		'index' => array(),
		'newuser' => array(),
		'snewuser' => array(
			array( 
				post => 'user', 
				regex => '/^[a-z]+$/',
			),
			array( post => 'pass1', nonEmpty => true ),
			array( post => 'pass2', nonEmpty => true ),

			# The recaptcha fields are optional if not using reCAPTCHA.
			array( post => 'recaptcha_challenge_field',
					optional => RECAPTCHA_ARGS_OPTIONAL ),
			array( post => 'recaptcha_response_field', 
					optional => RECAPTCHA_ARGS_OPTIONAL ),
		),
	);

	function index()
	{
		# Load the user's sent friend requests
		$users = dbQuery( "SELECT * from user" );
		$this->vars['users'] = $users;
	}

	function newuser()
	{
	}

	function snewuser()
	{
		$user = $this->args['user'];
		$pass1 = $this->args['pass1'];
		$pass2 = $this->args['pass2'];

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

		if ( $pass1 != $pass2 )
			$this->userError( "password mismatch", "" );

		$connection = new Connection;
		$connection->openLocal();
		$connection->newUser( $user, $pass1 );

		$this->siteRedirect( "/" );
	}
}
?>
