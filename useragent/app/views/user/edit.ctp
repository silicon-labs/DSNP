<table><tr>

<td id="leftcol">
<div id="details">
<h2><?php echo $USER['display_short'];?></h2>
</div>
</td>

<td id="activity">

<div class="content">

<?php 
echo $form->create( null, array( 'url' => "/$USER_NAME/user/sedit"));
echo $form->input('name');
echo $form->input('email');
echo $form->hidden( 'id' );
echo $form->end('Update');
?>

</div>

</td>

</tr></table>
