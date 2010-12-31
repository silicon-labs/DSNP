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
	$query_result = mysql_query($query);
	
	if ( ! $query_result )
		userError( EC_DATABASE_ERROR, array( 'query failed: ' . mysql_error() ) );

	$checkedMapping = false;
	if ( is_bool( $query_result ) ) {
		# Return the boolean directly. 
		return $query_result;
	}
	else {
		# Collect the results and return.
		$mapping = array();
		$classDef = array();
		while ( $row = mysql_fetch_assoc($query_result) ) {
			if ( !$checkedMapping ) {
				$checkedMapping = true;

				foreach ( $row as $key => $value ) {
					$pos = strpos( $key, '.' );
					if ( $pos !== false ) {
						$class = substr( $key, 0, $pos );
						$field = substr( $key, $pos + 1, strlen( $key ) - pos - 1 );

						$mapping[$key] = array( $class, $field );
						$classDef[$class] = 1;
					}
				}
			}

			if ( count( $mapping ) ) {
				foreach ( $classDef as $class => $value )
					$row[$class] = array();

				foreach ( $row as $key => $value ) {
					if ( isset( $mapping[$key] ) ) {
						$class = $mapping[$key][0];
						$field = $mapping[$key][1];
						$row[$class][$field] = $row[$key];
					}
				}
			}
			$result[] = $row;
		}
		return $result;
	}
}

# Connect to the database.
if ( ! mysql_connect( $CFG['DB_HOST'], $CFG['DB_USER'], $CFG['DB_PASS'] ) )
	userError( EC_DATABASE_ERROR, array( 'could not connect to database' ) );
if ( ! mysql_select_db( $CFG['DB_DATABASE'] ) )
	userError( EC_DATABASE_ERROR, array( 'could not select database ' . $CFG['DB_DATABASE'] ) );
	
?>
