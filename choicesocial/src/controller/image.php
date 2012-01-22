<?php
class ImageController extends Controller
{
	function imageDir()
	{
		return PREFIX . "/var/lib/choicesocial/{$this->CFG['NAME']}/data/{$this->USER['USER']}";
	}

	function viewImage( $file )
	{
		/* Find the image in the database. */
		$path = $this->imageDir() . "/$file";

		$stat = stat( $path );
		$size = $stat['size'];

		header("Content-Type: image/jpeg");
		header("Content-Size: $size");
		header("Cache-Control: max-age=2419200");
		readfile($path);

		$this->hasView = false;
	}
}
?>
