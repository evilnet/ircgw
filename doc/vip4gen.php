<?php
/*
 * This script is a sample PHP script demonstrating how ircgw generates a
 * virtual IPv4 IP address from an IPv6 IP address.
 *
 * Description:
 * ==========
 * First we check to see if the IPv6 IP is in the subnet 2002::/16, if it
 * is then we take the 3rd, 4th, 5th and 6th bytes and use those as the a
 * real IPv4 IP.
 *
 * If the above condition is not met we then generate 3 MD5 hashes using
 * bytes 1 to 8 for the first hash, 9 to 12 for the second hash, and 13
 * to 16 for the third hash. We then take byte 4 from the first hash,
 * byte 8 from the second and byte 12 from the third to make up the last
 * 3 bytes of an IP address in the 0.0.0.0/8 subnet.
 *
 * We use the 0.0.0.0/8 subnet simply to ensure that the virtual IP
 * address generated does not conflict with a real IPv4 IP address.
 * Using the 3 hashes in the way we do allows users/ircop to ban IPv6
 * blocks using a /64, /96 or /128 block of IPv6 IP's. To do so a user
 * or ircop simple has to ban either 0.A.* for the /64, 0.A.B.* for the
 * /96 and 0.A.B.C for the /128. Unfortunately however divisions other
 * then 64, 96 or 128 are not available due to limitations of the
 * generation method used.
 *
 */

if (isset($_GET['viewsource'])) {
	highlight_file(__FILE__);
	exit();
}

error_reporting(E_ALL & ~E_WARNING);

$ip = str_repeat(chr(0), 16);
if (isset($_GET['ip']) and ($_GET['ip'] != "")) {
	if (($ipin = inet_pton($_GET['ip'])) !== false) {
		$ip = $ipin;
	}
}
$ipstr = inet_ntop($ip);

if ((ord($ip[0]) == 0x20) and (ord($ip[1]) == 0x02)) {
	$ipout = sprintf("%d.%d.%d.%d", ord($ip[2]), ord($ip[3]), ord($ip[4]), ord($ip[5]));
} elseif ((ord($ip[0]) == 0x20) and (ord($ip[1]) == 0x01) and (ord($ip[2]) == 0x00) and (ord($ip[3]) == 0x00)) {
	$ipout = sprintf("%d.%d.%d.%d", (ord($ip[12]) ^ 0xFF), (ord($ip[13]) ^ 0xFF), (ord($ip[14]) ^ 0xFF), (ord($ip[15]) ^ 0xFF));
} else {
	$h1 = hash_init("md5");
	$h2 = hash_init("md5");
	$h3 = hash_init("md5");

	for ($i=0; $i<8; $i++) { hash_update($h1, $ip[$i]); }
	for ($i=8; $i<12; $i++) { hash_update($h2, $ip[$i]); }
	for ($i=12; $i<16; $i++) { hash_update($h3, $ip[$i]); }

	$ho1 = hash_final($h1, true);
	$ho2 = hash_final($h2, true);
	$ho3 = hash_final($h3, true);

	$ipout = sprintf("0.%d.%d.%d", ord($ho1[3]), ord($ho2[7]), ord($ho3[11]));
}

printf("%s => %s\n", $ipstr, $ipout);

?>
