
<div id="leftcol">
<div class="content">
<h2><?php echo $USER_NAME;?></h2>
</div>
</div>

<div id="activity">

<div class="content">


<?php echo $form->create( null, array( 'url' => "/$USER_NAME/user/sedit")); ?>

<?php echo $form->input('name'); ?>
<?php echo $form->input('email'); ?>

<?php echo $form->hidden( 'id' ); ?>

<?php echo $form->end('Update'); ?>

</div>


</div>
