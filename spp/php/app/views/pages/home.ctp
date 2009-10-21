<?php

global $CFG_DB_HOST;
global $CFG_DB_USER;
global $CFG_ADMIN_PASS;
global $CFG_DB_DATABASE;
global $CFG_URI;

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

# Look for the user/pass combination.
$query = "SELECT user FROM user";
$result = mysql_query($query) or die('Query failed: ' . mysql_error());


?>

<h2>Secure Personal Publishing</h2>

<p>Installation: <?php print $CFG_URI;?>

<p>
<a href="admin/newuser.php">create new user</a>

<h3>Users</h3>
<p>
<?php

while ( $row = mysql_fetch_assoc($result) )
    echo '<a href="' . $row['user'] . '/"/>' . $row['user'] . '</a><br>';
?>

