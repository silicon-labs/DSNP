<?php
class ImageController extends Controller
{
	function viewImage( $file )
	{
		/* Find the image in the database. */
		$path = "{$this->CFG[PHOTO_DIR]}/{$this->USER[USER]}/$file";

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
