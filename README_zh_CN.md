# XXTEA 加密算法的 PHP 实现

## 简介

XXTEA 是一个快速安全的加密算法。本项目是 XXTEA 加密算法的 PHP 实现。

它不同于原始的 XXTEA 加密算法。它是针对字符串进行加密的，而不是针对 uint32 数组。同样，密钥也是字符串。

## 安装

下载 xxtea.php，然后把它放在你的开发目录下就行了。

## 使用

```php
<?php
    require_once("xxtea.php");
    $str = "Hello World! 你好，中国！";
    $key = "1234567890";
    $encrypt_data = xxtea_encrypt($str, $key);
    $decrypt_data = xxtea_decrypt($encrypt_data, $key);
    if ($str == $decrypt_data) {
        echo "success!";
    } else {
        echo "fail!";
    }
?>
```
