<?php

include("auth.php");

$password = $_POST["password"];
$key = $_POST["key"];

// Pretty print
function p($var)
{
  print_r($var);
}

if(!isset($key))
{
  $key = "1c020611e3b753925ffc8af8745c0556";
}
else
{
  if(!is_string($key) || strlen($key)>5)
  {
    p("Unacceptable key!");
    die;
  }
}

$unlockedPassage = preg_replace($password, $key, $lockedPassage);
if($unlockedPassage === $actualPassage)
{
  p("Congrats! you found the correct password :): ");
  p($f);
}
else
{
  p("You must enter the correct password to get the flag!<br />");
  p($actualPassage);
}
