<?

#
# Formats and executes a database query. This is printf-style, but using a custom
# set of conversion specifiers. Returns the whole result set.
# It supports the following conversion specifiers
#
# %e  string, adds quotes.
# %l  long (integer)
# %L  long (integer)
#
function dbQuery()
{
	$args = func_get_args();
	$rest = $args[0];
	$nextArg = 1;

	$query = '';
	while ( true ) {
		$pos = strpos( $rest, '%' );
		if ( $pos === false ) {
			$query = $query . $rest;
			break;
		}

		$first = substr( $rest, 0, $pos);
		$char = substr( $rest, $pos + 1, 1 );
		$rest = substr( $rest, $pos + 2 );

		$query = $query . $first;

		switch ( $char ) {
			case 'e':
				$query = $query . "'" . 
						mysql_real_escape_string($args[$nextArg++]) . "'";
				break;
			case 'l':
				$query = $query . $args[$nextArg++];
				break;
			case 'L':
				$query = $query . $args[$nextArg++];
				break;
		}
	}

	$result = array();
	$query_result = mysql_query($query) or die( 'Query failed: ' . 
			mysql_error() . "\n" );
	if ( is_bool( $query_result ) ) {
		# Return the boolean directly. 
		return $query_result;
	}
	else {
		# Collect the results and return.
		while ( $row = mysql_fetch_assoc($query_result) )
			$result[] = $row;
		return $result;
	}
}

# Connect to the database.
mysql_connect( $CFG['DB_HOST'], $CFG['DB_USER'], $CFG['DB_PASS'] )
	or die("ERROR: could not connect to database\n");
mysql_select_db( $CFG['DB_DATABASE'] ) 
	or die('ERROR: could not select database ' . $CFG['DB_DATABASE'] . "\n" );
	
?>
