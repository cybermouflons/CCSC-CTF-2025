<?php

// Load Libraries
require('../vendor/autoload.php');
use HeadlessChromium\BrowserFactory;
use HeadlessChromium\Cookies\Cookie;

function startsWith($string, $startString) { 
	$len = strlen($startString); 
	return (substr($string, 0, $len) === $startString); 
}

$result = false;
if (
	$_SERVER['REQUEST_METHOD'] == 'POST' &&
	isset($_POST['url'])
) {
	$url = $_POST['url'];

	if (!startsWith($url, 'http://localhost/index.php?')) {
		$result = 'Error! Invalid URL.';
	}
	else {
		$flag = trim(file_get_contents('../flag.txt', true));

		// starts headless Chrome
		$browserFactory = new BrowserFactory();
		$browser = $browserFactory->createBrowser([
			'headless' => true,
			'windowSize' => [1920, 945],
			'disableNotifications' => true,
			'noSandbox' => true,
			'customFlags' => [
				//'--incognito',
				'--no-sandbox',
				'--disable-gpu',
				'--disable-dev-shm-usage',
				'--disable-setuid-sandbox'
			]
		]);

		try {
			// Creates a new page
			$page = $browser->createPage();

			//$page->setCookies([
			//	Cookie::create('flag', $flag, [
			//		'domain' => 'localhost',
			//		'expires' => time() + (60 * 60) // expires in 1 hour
			//	])
			//])->await();

			// Navigate to an URL
			$page->navigate('http://localhost/bot.php')->waitForNavigation();
			$page->evaluate("window.localStorage.setItem('flag', `$flag`)")->getReturnValue();

			// Navigate to an URL
			$page->navigate($url)->waitForNavigation();
			sleep(5);
			$result = 'Page was visited.';
		}
		catch(Exception $e) {
			$result = 'Failed to visit page.';
			//var_dump($e);
		}
		finally {
			// Close browser
			$browser->close();
		}
	}
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Visit Page</title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
</head>
<body>
	<div class="container my-3" style="width: 600px;">
		<h2>🤖 Bot</h2>
		<form method="POST" autocomplete="off">
			<div class="mb-3">
				<label for="url" class="form-label">URL 2 Visit</label>
				<input type="text" class="form-control" id="url" aria-describedby="url-help" name="url" value="http://localhost/index.php?xss=payload" autocomplete="off"/>
				<div id="url-help" class="form-text">The URL should start with "http://localhost/index.php?".</div>
			</div>
			<div class="text-end">
				<button type="submit" class="btn btn-primary">Visit</button>
			</div>
		</form>
		<?php if ($result) { ?>
		<div class="card mt-3">
			<div class="card-body">
				<code><?=$result;?></code>
			</div>
		</div>
		<?php } ?>
	</div>
</body>
</html>
