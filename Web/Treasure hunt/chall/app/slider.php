<?php
session_start();
if (!isset($_SESSION["username"]) OR !isset($_SESSION["password"])){
	header('Location: index.php');
}
?>
<html>
	<head>
		<meta charset="utf-8"/>
		<title>Report</title>
		<link rel="stylesheet" href="css/slider.css"/>

	</head>


	<body>
		<center>
			<h1>My personal collection</h1>
			<img id="imageMission" src="images/slides/001.jpg" alt="photo_mission"/>
		</center>

		<script> 


			function sleep(ms) {
			  return new Promise(resolve => setTimeout(resolve, ms));
			}

			async function changeImage(){
				await sleep(1000);
				var imageName = "";
				for (let i=2; i<=30; i++){
					if (i < 10){
						imageName = "00"+i+".jpg";
					}else{
						imageName = "0"+i+".jpg";
					}
					document.getElementById("imageMission").src="images/slides/"+imageName;
					await sleep(1000);
					console.log(imageName);
				}
				document.getElementById("imageMission").src="images/slides/001.jpg";
				changeImage();
			}
			changeImage();
			
		</script>
	
	</body>
<!--Note for the booty hunters: nice you’re one step closer to my treasure !-->
<!-- Did I ever tell you that I loved pictures ? Those might be more important that what you think :p -->

</html>
