<?php

$CFG_DB_HOST = Configure::read('CFG_DB_HOST');
$CFG_DB_USER = Configure::read('CFG_DB_USER');
$CFG_ADMIN_PASS = Configure::read('CFG_ADMIN_PASS');
$CFG_DB_DATABASE = Configure::read('CFG_DB_DATABASE');

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

# Look for the user/pass combination.
$query = "SELECT user FROM user_ua";
$result = mysql_query($query) or die('Query failed: ' . mysql_error());

?>

<table><tr>

<td id="leftcol">

<div class="content">

<h3>DSNP User-Agent One</h3>

<p>
<a href="admin/newuser">create new user</a>

</div>
</td>

<td id="activity">

<div class="content">
<h2>Users</h2>
<p>
<?php

$count = 0;
while ( $row = mysql_fetch_assoc($result) ) {
    echo '<a href="' . $row['user'] . '/"/>' . $row['user'] . '</a>&nbsp;&nbsp;&nbsp;';
	if ( ++$count % 5 == 0 ) {
		echo "<br>\n";
	}
}
?>
</div>

</td>

</tr></table>
