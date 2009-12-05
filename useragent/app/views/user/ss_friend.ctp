<?php

/* 
 * Copyright (c) 2007, Adrian Thurston <thurston@complang.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

include('functions.php');

?>

<div id="leftcol">

<div id="details">

<h2><?php print $USER['display_short'];?></h2>

</div>

<div id="friend_list">

<h3>Friend List</h3>

<?php

foreach ( $friendClaims as $row ) {
	$name = $row['FriendClaim']['name'];
	$dest_id = $row['FriendClaim']['identity'];

	if ( $dest_id == $BROWSER['identity'] ) {
		echo "you: <a href=\"${dest_id}\">";
		if ( isset( $name ) )
			echo $name;
		else
			echo $dest_id;
		echo "</a> <br>\n";
	}
	else {
		echo "<a href=\"${dest_id}cred/sflogin?h=" . 
			urlencode( $_SESSION['hash'] ) . "\">";
		if ( isset( $name ) )
			echo $name;
		else
			echo $dest_id;
		echo "</a> <br>\n";
	}
}

?>

</div>

</div>

<div id="activity">

<div class="content">

<h3>Wish Lists</h3>

<?php

#echo "<pre>";
#print_r( $BROWSER );
#echo " </pre>";

foreach ( $friendClaims as $row ) {
	$name = $row['FriendClaim']['name'];
	$dest_id = $row['FriendClaim']['identity'];
	$id = $row['FriendClaim']['id'];

	echo $html->link( $name, "/$USER_NAME/wish/view/$id" );
	echo "<br>\n";
}

//echo "<pre>"; print_r( $givesTo ); echo "</pre>";
?>

<font size=4>
Hello <?php print $BROWSER['name'];?>, you are buying a gift for ... &nbsp;&nbsp;

<span id="gift" style="color: #ffffff">
<?php print $givesTo['FriendClaim']['name'];?>
</span>
</font>

<script type="text/javascript">
function fade( elId )
{
	var el = document.getElementById(elId);
	el.rgb += el.direction;
	if ( el.direction > 0 && el.rgb > el.up_thresh ) {
		//el.rgb = el.up_thresh;
		//el.direction = el.direction * -1;
		clearInterval( interval_id );
		//document.location = "/secret_santa/";
	}
	else if ( el.direction < 0 && el.rgb < el.down_thresh ) {
		el.rgb = el.down_thresh;
		el.direction = el.direction * -1;
	}

	var newColour = "rgb("+el.rgb+','+el.rgb+','+el.rgb+")";
	el.style.color = newColour;
}

function init( elId, val )
{
	var el = document.getElementById(elId);
	el.rgb = val;
	el.direction = -10;
	el.up_thresh = 500;
	el.down_thresh = -100;                                 
}                                                              
                                                               
var elId = "gift";                                         
var interval_id;
function show()
{
	interval_id = setInterval("fade('" + elId + "')", 70);     
}
</script>                   

<input type="button" onClick="init(elId,500);show();" name="show" value="show" width="10%">

</div>
</div>
