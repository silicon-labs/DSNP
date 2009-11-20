
<div id="leftcol">
<div class="content">
<h2><?php echo $USER['display_short'];?></h2>
</div>
</div>

<div id="activity">

<div class="content">

<?php 
echo $form->create( null, array( 'url' => "/$USER_NAME/user/sedit"));
echo $form->input('name');
echo $form->input('email');
echo $form->hidden( 'id' );
echo $form->end('Update');
?>

</div>

</div>
