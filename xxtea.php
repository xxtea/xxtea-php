<?php
/**********************************************************\
|                                                          |
| xxtea.php                                                |
|                                                          |
| XXTEA encryption algorithm library for PHP.              |
|                                                          |
| Encryption Algorithm Authors:                            |
|      David J. Wheeler                                    |
|      Roger M. Needham                                    |
|                                                          |
| Code Author: Ma Bingyao <mabingyao@gmail.com>            |
| LastModified: Feb 15, 2014                               |
|                                                          |
\**********************************************************/

if (!extension_loaded('xxtea')) {

	// private const

	define("XXTEA_DELTA", 0x9E3779B9);

	// private functions

    function xxtea_long2str($v, $w) {
        $len = count($v);
        $n = ($len - 1) << 2;
        if ($w) {
            $m = $v[$len - 1];
            if (($m < $n - 3) || ($m > $n)) return false;
            $n = $m;
        }
        $s = array();
        for ($i = 0; $i < $len; $i++) {
            $s[$i] = pack("V", $v[$i]);
        }
        if ($w) {
            return substr(join('', $s), 0, $n);
        }
        else {
            return join('', $s);
        }
    }

    function xxtea_str2long($s, $w) {
        $v = unpack("V*", $s. str_repeat("\0", (4 - strlen($s) % 4) & 3));
        $v = array_values($v);
        if ($w) {
            $v[count($v)] = strlen($s);
        }
        return $v;
    }

    function xxtea_int32($n) {
    	return ($n & 0xffffffff);
    }

    function xxtea_mx($sum, $y, $z, $p, $e, $k) {
        return ((($z >> 5 & 0x07ffffff) ^ $y << 2) + (($y >> 3 & 0x1fffffff) ^ $z << 4)) ^
               (($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z));
    }

    function xxtea_fixk($k) {
        if (count($k) < 4) {
            for ($i = count($k); $i < 4; $i++) {
                $k[$i] = 0;
            }
        }
        return $k;
    }
	// public functions

    // $str is the string to be encrypted.
    // $key is the encrypt key. It is the same as the decrypt key.
    function xxtea_encrypt($str, $key) {
        if ($str == "") {
            return "";
        }
        $v = xxtea_str2long($str, true);
        $k = xxtea_fixk(xxtea_str2long($key, false));
        $n = count($v) - 1;
        $z = $v[$n];
        $y = $v[0];
        $q = floor(6 + 52 / ($n + 1));
        $sum = 0;
        while (0 < $q--) {
            $sum = xxtea_int32($sum + XXTEA_DELTA);
            $e = $sum >> 2 & 3;
            for ($p = 0; $p < $n; $p++) {
                $y = $v[$p + 1];
                $z = $v[$p] = xxtea_int32($v[$p] + xxtea_mx($sum, $y, $z, $p, $e, $k));
            }
            $y = $v[0];
            $z = $v[$n] = xxtea_int32($v[$n] + xxtea_mx($sum, $y, $z, $p, $e, $k));
        }
        return xxtea_long2str($v, false);
    }

    // $str is the string to be decrypted.
    // $key is the decrypt key. It is the same as the encrypt key.
    function xxtea_decrypt($str, $key) {
        if ($str == "") {
            return "";
        }
        $v = xxtea_str2long($str, false);
        $k = xxtea_fixk(xxtea_str2long($key, false));
        $n = count($v) - 1;

        $z = $v[$n];
        $y = $v[0];
        $q = floor(6 + 52 / ($n + 1));
        $sum = xxtea_int32($q * XXTEA_DELTA);
        while ($sum != 0) {
            $e = $sum >> 2 & 3;
            for ($p = $n; $p > 0; $p--) {
                $z = $v[$p - 1];
                $y = $v[$p] = xxtea_int32($v[$p] - xxtea_mx($sum, $y, $z, $p, $e, $k));
            }
            $z = $v[$n];
            $y = $v[0] = xxtea_int32($v[0] - xxtea_mx($sum, $y, $z, $p, $e, $k));
            $sum = xxtea_int32($sum - XXTEA_DELTA);
        }
        return xxtea_long2str($v, true);
    }
}
?>