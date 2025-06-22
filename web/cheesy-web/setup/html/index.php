<?php

$nonce = 'nonce-' . bin2hex(openssl_random_pseudo_bytes(32));
header("Content-Security-Policy: default-src 'none';script-src '$nonce';");
if (isset($_GET["xss"])){

?>
<!DOCTYPE html>
<html lang="en">
<body>
<script type="text/javascript" nonce="<?=$nonce;?>">
(function() {
	let d1 = document.createElement('div');
	let flag = window.localStorage.getItem('flag') || 'ECSC{f4ke-f1aG}';
	window.localStorage.removeItem('flag');
	let d2 = document.createElement('div');
	d2.appendChild(document.createTextNode('Nothing to see here...'));
	d2.appendChild(document.createComment('Here is your flag: ' + flag));
	document.body.appendChild(d1);
	d1.attachShadow({ mode: "closed" }).appendChild(d2);
	window.addEventListener('message', message => {
		if (message.source === window) return;
		if (event.data && event.data.hasOwnProperty('style')) {
			for (const [key, value] of Object.entries(event.data.style)) {
				if (key.startsWith('-')) continue;
				d2.style[key] = value;
			}
		}
	});
})();
</script>
<?php
	echo $_GET["xss"];
?>
</body>
</html>
<?php
}
else {
	show_source("index.php");
}

// Use bot.php to access the flag

