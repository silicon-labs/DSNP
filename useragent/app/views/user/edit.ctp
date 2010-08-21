<table><tr>

<td id="leftcol">
<div id="details">
<h2><?php echo $USER['display_short'];?></h2>
</div>
</td>

<td id="activity">

<div class="content">

<form method="post" action="/age/user/sedit">
<fieldset style="display:none;"><input type="hidden" name="_method" value="PUT" /></fieldset>
<div class="input text">
	<label for="UserName">Name</label>
	<input name="name" type="text" maxlength="50" 
	value="<?php echo htmlspecialchars( $user[0]['name'] )?>" 
	id="UserName" />
</div>
<div class="input text">
	<label for="UserEmail">Email</label>
	<input name="email" type="text" maxlength="50" value="" id="UserEmail" />
</div>
<input type="hidden" name="id" value="<? echo $USER['id']; ?>" id="UserId" />
<div class="submit">
<input type="submit" value="Update" />
</div>

</form>

</div>

</td>

</tr></table>
