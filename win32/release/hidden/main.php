<?php include "./data/text/text.php" ?>

<?php
function YouTube($videoUrl)
{
	if(strstr($_SERVER['HTTP_USER_AGENT'],'iPhone') || strstr($_SERVER['HTTP_USER_AGENT'],'iPod') || strstr($_SERVER['HTTP_USER_AGENT'],'iPad')) 
	{
?>
		<object class="video"><param name="movie" value="<?php echo $videoUrl; ?>?hl=en_GB&amp;"></param><param name="allowFullScreen" value="true"></param><param name="allowscriptaccess" value="always"></param><embed src="<?php echo $videoUrl; ?>" type="application/x-shockwave-flash" class="ovideo" allowscriptaccess="always" allowfullscreen="true"></embed></object>
<?php
	}
	else
	{
?>
    <iframe class="video" src="<?php echo $videoUrl; ?>"></iframe>
<?php
	}
}
?>

<div class="four_fourth firstcols">
  <section id="mainthecontent">

    <article>
      <div class="clear"></div>

      <div class="four_fourth">

        <h1><?php echo $gUkazky[$gLangId]; ?></h1>
        
		<!-- next video upcomming - text under -->
		<section>
			<div class="eight columns firstcols">
				<?php YouTube("http://www.youtube.com/v/7vFiWKGlXWs"); ?>
			</div>	
				
			<div class="four columns lastcols" style="margin-left:-40px">
				<br><br><br>
				<?php echo $gRokHadaText[$gLangId]; ?>
			</div>	
			<div class="clear"></div>
			<br><br>
		</section>

        <h1><?php echo $gPromo[$gLangId]; ?></h1>
        <div>
					<?php YouTube("http://www.youtube.com/embed/Ehb_UuFwr8s"); ?>
					<p></p>
        </div>
		
        <h1><?php echo $gMedia[$gLangId]; ?></h1>
        <div>			                                                                                                                  

					<?php YouTube("http://www.youtube.com/embed/tU_CYo076MM"); ?>

					<?php YouTube("http://www.youtube.com/v/qLFI5XjWeIc"); ?>

					<a href="http://www.tvr.sk/tvprogram/ruzinovske-spravy/ruzinovske-spravy/2013-02-12-173000" target="_blank">
						<img class="video" src="./imgs/TVR.jpg" alt="TVR - 5:30" title="TVR - 5:30" style="alignleft frame" />
					</a>
        </div>
		
      </div>
    </article>

  </section>
</div>

<div class="clear"></div>
