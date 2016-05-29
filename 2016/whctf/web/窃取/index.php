<?php

echo "<ul><li><a href='index.php?id=1'>Companionship of Books</a></li><li><a href='index.php?id=2'>If I Rest, I Rust</a></li><li><a href='index.php?id=3'>Three Days to See</a></li><li><a href='index.php?id=4'>Youth</a></li></ul>";

$db_user='whctf';
$db_password='wwwhhhccctttfff';
$db_host='localhost';
$db_database='web_sqli';
$con =mysql_connect($db_host,$db_user,$db_password) or die('Not connect');
mysql_select_db($db_database,$con) or dir('Not select');
mysql_query('SET NANES UTF8');

if(isset($_GET["id"])){
  $id = $_GET["id"];
  $sql = "select content from article where id = '".$id."'";
  $result = mysql_query($sql);
  echo mysql_fetch_array($result)[0];
}
?>
