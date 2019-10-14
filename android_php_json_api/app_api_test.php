<?php

define( API_PASSWORD, "test" );


// client test
{
	date_default_timezone_set( 'Asia/Seoul' );
	$timestamp = strval( time() );

	//$secret_key = bin2hex( random_bytes(20) );
	//$secret_key = '2d6e5824b97e71f263349d1e0bc3989d1ebaa335';
	$secret_key = '1234567890123456789012345678901234567890';

	$plaintext =
'
{
"timestamp":' . "\"$timestamp\"" . "," .
'
"msg1":"msg1_val",
"msg2":"msg2_val"
}
';
var_dump( $plaintext );
echo "secret key = " . $secret_key . "\n";
echo "\n";


	{
		$password = API_PASSWORD;
		$privkey = openssl_pkey_get_private( 'file://./keys/4096/private_enc.pem', $password );
		$pubkey = openssl_pkey_get_public( 'file://./keys/4096/public.pem' );
		if ( $pubkey === false ) {
			//echo "" . make_json_error( "false", "ERROR: public key" );
			echo "ERROR: public key";
			exit;
		}

		$compress = gzencode( $plaintext );
		if ( $compress === false ) {
			echo "ERROR: encryption";
			exit;
		}

		$result = openssl_public_encrypt( $compress, $encrypt, $pubkey, OPENSSL_PKCS1_OAEP_PADDING );
		if ( $result === false || $encrypt === false ) {
			echo "ERROR: encryption";
			exit;
		}
		$encrypt = base64_encode( $encrypt );
	}

	$post_data = array(
		"data" => $encrypt,
		"timestamp" => $timestamp,
		"verify" => hash("sha256", $plaintext . $secret_key) // hash: SHA256(plain-text data + secret key)
	);

	echo "post data (encrypt) = \n";
	var_dump( $post_data );
	echo "\n";


	// decrypt
	$encrypt = base64_decode( $encrypt, true );
	$result = openssl_private_decrypt( $encrypt, $decrypt, $privkey, OPENSSL_PKCS1_OAEP_PADDING );
	if ( $result === false || $decrypt === false ) {
			echo "ERROR: decryption";
			exit;
	}

	$decompress = gzdecode( $decrypt );
	if ( $decompress === false ) {
			echo "ERROR: decryption";
			exit;
	}

	$result = json_decode( $decompress, true );

echo "result (decrypt) =\n";
var_dump($result);


	$host = "http://127.0.0.1/test/app_api.php";
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $host);
	//curl_setopt($ch, CURLOPT_PORT, $port);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
	//curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/json")); 
	curl_setopt($ch, CURLOPT_HTTPHEADER, "Content-Type: application/x-www-form-urlencoded");
	curl_setopt($ch, CURLOPT_POST, TRUE);
	//curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($text_data));
	curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
	//curl_setopt($ch, CURLOPT_VERBOSE, true);
	$result = curl_exec($ch);

	echo $result . "\n";


	//sleep( 4 );
	//$result = curl_exec($ch);
	//echo $result . "\n";
exit;
}


//header( "Location: " . "test.php?data=" . urlencode($encrypt) );
//exit;

?>
