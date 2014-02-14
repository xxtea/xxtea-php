<?php
    require_once("xxtea.php");
	$str = "Hello World! 你好，中国！";
	$key = "1234567890abcdef";
	$encrypt_data = xxtea_encrypt($str, $key);
	$decrypt_data = xxtea_decrypt($encrypt_data, $key);
	if ($str == $decrypt_data) {
		echo "success!";
	} else {
		echo "fail!";
	}
?>