<?php
$con = mysql_connect("localhost","studentGrades","tttuuuccctttfff");
if (!$con)
  {
  die('Could not connect: ' . mysql_error());
  }

mysql_select_db("tuctf2016_StudentGrades", $con);

$data = $_POST["name"];

$md5 = substr($data,strlen($data)-32);

$name = substr($data,0,strlen($data)-33);

if ($md5 === md5($name)) {
  $sql = "SELECT * FROM tuctf_grades WHERE name LIKE '%".$name."%';";
  $result = mysql_query($sql);
  $response = "<!--HI!--><!--Good auth!--><!--".$sql."--><tr><th>Name</th><th>Grade</th></tr>";
  while($row = mysql_fetch_array($result))
  {
    $response = $response."<tr><td>".$row['name']."</td><td>".$row['grade']."</td></tr>";
  }
  echo $response;
}else {
  echo "illeagle query!";
}

mysql_close($con);
?>
