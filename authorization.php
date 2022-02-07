<?php

$expirationTime = 2 * 3600;

function hasAccess($key, $timestamp, $username) {
	if($timestamp + $expirationTime < time())
		return false;
	return (strcmp($key, md5($username."PRIVATE_KEY".$timestamp)) == 0);
}
?>
