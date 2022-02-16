<?php
session_start();

class TokenAuthentication
{
	private $expirationTime = 2 * 3600;
	private $salt;

	function __construct()
	{
		if (!is_file("secrets/salt"))
			exit("Salt file is missing");
		$this->salt = file_get_contents("secrets/salt");
	}

	function hasAccess($token, $timestamp, $username)
	{
		if ($timestamp + $this->expirationTime < time())
			return false;
		return (strcmp($token, md5($username . trim($this->salt) . $timestamp)) == 0);
	}

	function getToken($timestamp, $username)
	{
		return md5($username . $this->salt . $timestamp);
	}

	function auth()
	{
		if (isset($_GET['key']) && isset($_GET['timestamp']) && isset($_GET['username']))
			return $this->hasAccess($_GET['key'], $_GET['timestamp'], $_GET['username']);
		if (isset($_POST['key']) && isset($_POST['timestamp']) && isset($_POST['username']))
			return $this->hasAccess($_POST['key'], $_POST['timestamp'], $_POST['username']);
	}
}

class PasswdAuthentication
{
	private $credentials;
	function __construct()
	{
		if (!is_file('secrets/passwd.csv')) //TODO change this to be in secrets
			exit("passwd file is missing");
		$this->credentials = array_map('str_getcsv', file('secrets/passwd.csv')); //TODO and here
	}

	function isAdmin()
	{
		foreach ($this->credentials as $credential) {
			if ($credential[0] == $_SESSION['username'] && $credential[2] == 'true')
				return true;
		}
	}

	function isUsernamePasswd($username, $passwd)
	{
		foreach ($this->credentials as $credential) {
			if ($credential[0] == $username && $credential[1] == $passwd)
				return true;
		}
		return false;
	}

	function auth()
	{
		global $failedLogIn;
		if (!isset($_POST['username']) ||  !isset($_POST['password']))
			return false;
		$isUsernamePasswd = $this->isUsernamePasswd($_POST['username'], $_POST['password']);
		if ($isUsernamePasswd)
			$_SESSION['username'] = $_POST['username'];
		else
			$failedLogIn = true;
		return $isUsernamePasswd;
	}
}

function isAuthenticated()
{
	if (isset($_SESSION["username"]))
		return true;
	$passwdAuthentication = new PasswdAuthentication();
	if ($passwdAuthentication->auth())
		return true;
	$tokenAuthentication = new TokenAuthentication();
	return $tokenAuthentication->auth();
}

function getUsername()
{
	if (isset($_SESSION["username"]))
		return $_SESSION["username"];
	if (isset($_GET['username']))
		return $_GET['username'];
	if (isset($_POST['username']))
		return $_POST['username'];
	else
		return "NOTLOGGEDIN";
}

function isAdmin()
{
	if (!isset($_SESSION["username"]))
		return false;
	$passwdAuthentication = new PasswdAuthentication();
	return $passwdAuthentication->isAdmin();
}

function printLogOut()
{
	if (!isset($_SESSION["username"]))
		return;
?>
	<nav class="navbar justify-content-end">
		<?php
		$username = strtolower(trim($_SESSION["username"], " "));
		echo "<strong>" . $username . "</strong>";
		?>
		<form action="" method="post">
			<button type="submit" class="btn btn-primary btn-sm" name="logout">Log Out</button>
		</form>
	</nav>
<?php
}

function printAuthForm()
{
?>
	<script>
		function validateForm() {
			var x = document.forms["myForm"]["username"].value;
			var y = document.forms["myForm"]["password"].value;
			if ((x == null || x == "") || (y == null || y == "")) {
				alert("You must fill in Username and Passwd!");
				return false;
			}
		}
	</script>
	<div class="w3-container">
		<div style="background-color:white;">
			<h2 style="text-align:left;"><strong>Checker</strong></h2>
		</div>
		<h3 class="form-signin-heading">You need to log in</h3>
	</div>
	<div class="form">
		<form class="form-signin" action="" method="post" name="myForm" onsubmit="return validateForm()">
			<input class="form-control" type="text" name="username" placeholder="Nume utlizator" />
			<input class="form-control" type="password" name="password" placeholder="Parola" />
			<button class="btn btn-lg btn-primary btn-block">login</button>
		</form>
	</div>
	<?php
	if (isset($failedLogIn)) {
	?>
		<div class="w3-container w3-orange" style="position:float; center:50%;">
			<h2 class="form-signin-heading" style="color:red;background-color:white; align:center;"> Combinatia nume utilizator, parola nu exista!</h2>
		</div>
<?php
	}
}

if (isset($_POST['logout'])) {
	unset($_SESSION['username']);
}
?>