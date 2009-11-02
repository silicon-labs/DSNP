
<div id="leftcol">
<div class="content">
<h2><?php echo $USER_NAME;?></h2>
</div>
</div>

<div id="activity">

<div class="content">


<form method="post" action="<?php echo $html->url( "/$USER_NAME/user/sedit" ); ?>">

<table>

<tr>
<td>Name:</td>
<td><input name="name" type="text"></td>
</tr>

</table>

<input type="submit">
</form>

</div>


</div>
