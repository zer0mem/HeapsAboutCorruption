<?php
	define("PATH", "./data/imgs/");
	$handle = opendir(PATH);
	
	if ($handle)
	{
		$imgs = array();
		
		{
			$file = "";
			do
			{
				$file = readdir($handle);
				if (false == $file)
					break;

				$file = strtolower(PATH.$file);
				if(is_dir($file) || !substr_count($file, ".jpg"))
					continue;

				$pos = strrpos($file, "/");
				if ($pos != false)
					array_push($imgs, $file);

			} while (false != $file);
			
			sort($imgs);
		}
		
		for($j = 0; $j < count($imgs); )
		{
?>
  <ul class="ts-gallery-col4">
<?php
			for ($i = 0; $i < 4; $i++)
			{
				if ($j >= count($imgs))
					break;
					
				$file = $imgs[$j];
		
				echo "<li";
				if (3 == $i)
					echo ' class="nomargin"';
				echo ">";

				$pos = strrpos($file, "/");
				if ($pos != false)
					$full_img = substr($file, 0, $pos + 1) . "orig" . substr($file, $pos);
?>

      <div class="ts-gallery-img">
        <a title="" data-rel="prettyPhoto[mixed]" href="<?php echo $full_img; ?>" class="image">
          <span class="rollover"></span>
          <img class="scale-with-grid" alt="" src="<?php echo $file; ?>" />
        </a>
      </div>
      <div class="ts-gallery-text ">
        <h2></h2>
      </div>
      <div class="ts-gallery-clear"></div>
    </li>
	
<?php
				$j++;
			}
?>
	<li class="ts-gallery-clear"></li>
  </ul>
<?php
		}
	}
?>
