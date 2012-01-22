<?

$CFG = null;

if ( isset($_SERVER['HTTP_HOST']) && isset($_SERVER['REQUEST_URI']) )
{
	$haystack = $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

	for ( $i = 0; $i < count( $CFG_ARRAY ); $i++ ) {
		$needle = $CFG_ARRAY[$i]['URI'];
		$needle = preg_replace( '/^[a-zA-Z]+:\/\//', '', $needle );
		$needle = preg_replace( '/\/$/', '', $needle );

		if ( strpos( $haystack, $needle ) === 0 ) {
			$CFG = $CFG_ARRAY[$i];
			return;
		}
	}
}

if ( isset( $CFG_COMM_KEY ) ) {
	for ( $i = 0; $i < count( $CFG_ARRAY ); $i++ ) {
		if ( $CFG_COMM_KEY == $CFG_ARRAY[$i]['COMM_KEY'] ) {
			$CFG = $CFG_ARRAY[$i];
			return;
		}
	}
}

if ( isset( $CFG_NAME ) ) {
	for ( $i = 0; $i < count( $CFG_ARRAY ); $i++ ) {
		if ( $CFG_NAME == $CFG_ARRAY[$i]['NAME'] ) {
			$CFG = $CFG_ARRAY[$i];
			return;
		}
	}
}

die("ERROR: a site configuration was not selected\n");

?>
