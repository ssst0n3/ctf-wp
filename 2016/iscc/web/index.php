<html>
<head>
Masel's secure site
</head>
<body>

<a href="setup-db.php">重置数据库</a>

<?php
$servername = '127.0.0.1';
$username = 'root';
$password = '';
$database = 'tmp';

error_reporting(0);
if($_POST["user"] && $_POST["pass"]) {
	$conn = mysqli_connect($servername, $username, $password, $database);
	if ($conn->connect_error) {
		die("Connection failed: " . mysqli_error($conn));
}
$user = $_POST["user"];
$pass = $_POST["pass"];

$sql = "select user from user where pw='$pass'";
echo '</br>';
echo $sql;
echo '</br>';
$query = mysqli_query($conn,$sql);
if (!$query) {
	printf("Error: %s\n", mysqli_error($conn));
	exit();
}
$row = mysqli_fetch_array($query);
var_dump($row);
//echo $row["pw"];
echo '</br>';
echo $row[user];
if ($row[user]){
	if ($row[user] == "flag" && $user=="flag") {
		echo "<p>Logged in! Flag: ****************** </p>";
	}
	else{
		echo "<p>Password is right, but it's not for the flag </p>";
	}
}
else {
    echo("<p>Wrong password!</p>");
  }
}

?>


<form method=post action=index.php>
<input type=text name=user value="flag">
<input type=password name=pass value="Password">
<input type=submit>
</form>
</body>
<a href="index.php.txt">Source</a>
</html>
