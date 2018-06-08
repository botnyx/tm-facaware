<?php

namespace botnyx\tmfacaware;

# \botnyx\tmfacaware\jwtdecode($jwt_pub_key)

class jwtdecode{
	
	private $jwt_public_key;
	private $payload = false;
	
	function __construct($jwt_public_key){
		if(!file_exists($jwt_public_key)){
			throw new \Exception("Public key missing (".$jwt_public_key.")",500);
		}
		
		$this->jwt_public_key=$jwt_public_key;
		
	} 
	
	public function decode($jwt_access_token,$algo=OPENSSL_ALGO_SHA256){
		#echo "JWTDECODE";
		//$token = json_decode($curlResponse);

		//$jwt_access_token = $token['access_token'];

		$separator = '.';

		if (2 !== substr_count($jwt_access_token, $separator, $algo)) {
			//throw new \Exception("Incorrect access token format");
			return false;
		}

		list($header, $payload, $signature) = explode($separator, $jwt_access_token);

		$decoded_signature = base64_decode(str_replace(array('-', '_'), array('+', '/'), $signature));

		// The header and payload are signed together
		$payload_to_verify = utf8_decode($header . $separator . $payload);

		// however you want to load your public key
		$public_key = file_get_contents($this->jwt_public_key);

		// default is SHA256
		$verified = openssl_verify($payload_to_verify, $decoded_signature, $public_key, $algo);

		if ($verified !== 1) {
			//throw new \Exception("Cannot verify signature");
			$this->payload = false;
			return false;
		}

		// output the JWT Access Token payload
		$decoded =  json_decode(base64_decode($payload));
		$this->payload = $decoded;
		
		return $decoded;
		
	}
	
	public function getPayload(){
		return $this->payload;
	} 
	
}