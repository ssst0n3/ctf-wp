<?php

$db_user='root';
$db_password='';
$db_host='localhost';
$db_database='iscc';
$con =mysql_connect($db_host,$db_user,$db_password) or die('Not connect');
mysql_select_db($db_database,$con) or dir('Not select');
mysql_query('SET NANES UTF8');

if(isset($_POST['username'])&&isset($_POST['password'])){
  $username = $_POST["username"];
  $username = str_replace(' ', '', $username);
  $password = $_POST["password"];
  $sql = "select password from admin where username = '".$username."'";
  $result = mysql_query($sql);
  $rowcount = mysql_num_rows($result);
  if ($rowcount == 0){
    echo '用户名错误';
  }else{
    while ($i = mysql_fetch_array($result)){
      if ($username === 'admin' and md5($password) === $i['password']){
        echo 'flag{51f52db9-5304-4dcf-acb1-6b0ec2e167f2}';
      }else{
        echo '密码错误';
      }
    }
  }
}else {
  echo '用户名或密码不能为空';
}
?>
