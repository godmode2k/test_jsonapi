<?php
// Android + PHP: Custom API test
// - hjkim, 2019.10.10


header('Content-Type: application/json');

date_default_timezone_set( 'Asia/Seoul' );
//echo date('Y/m/d/ H:i:s', time()) . "<br>";

define( API_PASSWORD, "test" );



// next: true/false (','), start: true/false (first)
function make_json($result, $key, $val, $next, $start) {
	if ( $start == true ) $result .= "{";
	if ( !empty($key) ) {
		$result .= "\"$key\": \"$val\"";
		if ( $next == true ) $result .= ",";
	}


	return $result;
}
function make_json_end($result, $next = false) {
	$result .= "}";
	if ( $next == true ) $result .= ",";

	return $result;
}
function make_json_error($val, $message = "") {
	//$result = make_json( "", "result", $val, false, true );
        $result = make_json( "", "result", $val, true, true );
        $result = make_json( $result, "message", $message, false, false );
	$result = make_json_end( $result );
	return $result;
}




function decryption($encrypt, &$result_raw) {
        $password = API_PASSWORD;
        $privkey = openssl_pkey_get_private( 'file://./keys/4096/private_enc.pem', $password );
        //$pubkey = openssl_pkey_get_public( 'file://./keys/4096/public.pem' );
        if ( $privkey === false ) {
                echo "" . make_json_error( "false", "ERROR: private key" );
                exit;
        }

        $encrypt = base64_decode( $encrypt, true );
        $result = openssl_private_decrypt( $encrypt, $decrypt, $privkey, OPENSSL_PKCS1_OAEP_PADDING );
        if ( $result === false || $decrypt === false ) {
                echo "" . make_json_error( "false", "ERROR: decryption" );
                exit;
        }

        $decompress = gzdecode( $decrypt );
        if ( $decompress === false ) {
                echo "" . make_json_error( "false", "ERROR: decryption" );
                exit;
        }

        $result = json_decode( $decompress, true );
		$result_raw = $decompress;
        return $result;
}



if ( !empty($_POST) ) {
	if ( isset($_POST['data']) && !empty($_POST['data'])
		&& isset($_POST['timestamp']) && !empty($_POST['timestamp'])
		&& isset($_POST['verify']) && !empty($_POST['verify']) ) {
echo "----------------------------------\n";
echo "(Server) received post data = \n";

var_dump( $_POST );


		//$headers = apache_request_headers();
		//foreach ($headers as $header => $value) {
		//	echo "$header: $value \n";
		//}
		//echo "headers:\n";
		//var_dump( $headers );



		$_result_raw = "";
		$_result_arr = decryption( $_POST['data'], $_result_raw );
		if ( !isset($_result_arr) || !is_array($_result_arr) ) {
			echo "" . make_json_error( "false" );
			exit;
		}

		var_dump($_result_arr);

		$_timestamp = $_result_arr['timestamp'];

		$server_timestamp = intval( time() );
		//echo "(Server) timestamp = " . $server_timestamp . "\n";
		error_log( "(Server) timestamp = " . $server_timestamp );
		// expire timestamp: timestamp(request) + 3 seconds
		if ( $server_timestamp > (intval($_timestamp) + 3) ) {
			//echo "Error: expired timestamp\n";
			//echo "server: " . $server_timestamp . "\n";
			//echo "request: " . $_timestamp . "\n";
			error_log( "Error: expired timestamp" );
			error_log( "server: " . $server_timestamp );
			error_log( "request: " . $_timestamp );
			echo "" . make_json_error( "false", "expired timestamp" );
			exit;
		}


		//! client's secret key (from DB)
		//$client_secret_key = '2d6e5824b97e71f263349d1e0bc3989d1ebaa335';
		$client_secret_key = '1234567890123456789012345678901234567890';


		//! verify
		$verify = $_POST['verify'];
		echo "(post data) verify = " . $verify . "\n";
		error_log( "(post data) verify = " . $verify );
		$verify2 = hash( "sha256", $_result_raw . $client_secret_key );
		echo "(Server) verify = " . $verify2 . "\n";
		error_log( "(Server) verify = " . $verify2 );
		if ( $verify != $verify2 ) {
			error_log( "Error: verify" );
			echo "" . make_json_error( "false", "verify" );
			exit;
		}
		error_log( "(Server) verified" );
		echo "(Server) verified" . "\n";
		var_dump( $_result_raw );




		$_timestamp = $_result_arr['timestamp'];
		$_msg1 = $_result_arr['msg1'];
		$_msg2 = $_result_arr['msg2'];

		$_timestamp = trim( $_timestamp );
		$_msg1 = trim( $_msg1 );
		$_msg2 = trim( $_msg2 );
echo "----------------------------------\n";
	}
}

