<?php session_start(); ?>
<html>

	<head>
		<meta charset="utf-8"/>
		<title>Login</title>
		<link rel="stylesheet" href="css/index.css"/>
</head>
<body>
	<form action="index.php" method=post>
			<div class="username">
				<img src="images/login/user.png"/>
				<input type="text" placeholder="Username" name="username" required>
			</div>
			<br />
			<div class="password">
				<img src="images/login/key.png"/>
				<input type="password" placeholder="Password" name="password" required>
			</div>
			<br />
			<button type="submit" class="loginButton">Login</button>
		</form>
	</body>
</html>

<?php

	if (isset($_SESSION["username"]) AND isset($_SESSION["password"])){
		header('Location: slider.php');
	}

	else if (isset($_POST["username"]) AND isset($_POST["password"])){

		$conn = new PDO("mysql:host=127.0.0.1;dbname=employees",'admin','Oi42oTR9SGDFGH');

		$username = $_POST["username"];
		$password = $_POST["password"];
		$md5Password = md5($password);
		$stmt = $conn->query("SELECT * FROM users WHERE username='$username' AND password='$md5Password'");

		$result = $stmt->fetch();

		if($result){
			$_SESSION["username"] = $result["username"];
			$_SESSION["password"] = $result["password"];
			header('Location: slider.php');

		}else{

			?><p id="errorMessage">Incorrect username or passowrd</p><?php
		}

		$conn->close();	
	}
		
?>
