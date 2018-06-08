<?php 


namespace botnyx\tmfacaware;

use ArrayAccess;
use Slim\Http\Request;
use Slim\Http\Response;



class cookiemanager {
	var $cookiedomain;
	
	var $jwt_public_key = false;
	
	var $httpOnlyPrefix			= "S";
	var $tokenCookieName 		= "SID";
	var $refreshTokenCookieName = "RID";
	var $expireCookieName 		= "EAT";
	
	function __construct($jwt_public_key = false){
		
		$this->jwt_public_key = $jwt_public_key;
		
		$this->cookiedomain = $_SERVER['HTTP_HOST'];
		$this->requestedUrl = $_SERVER['SCRIPT_URI']."?".$_SERVER['QUERY_STRING'];
		
	}
	
	
	public function verifyCookies(){
		
		if(!isset($_COOKIE[$this->httpOnlyPrefix.$this->tokenCookieName]) && !isset($_COOKIE[$httpOnlyPrefix.$refreshTokenCookieName]) ){
			// no valid cookie!
			$error = 'No cookies found!';
    		throw new Exception($error,404);
		}
		
		if(!isset($_COOKIE[$this->httpOnlyPrefix.$this->tokenCookieName]) && isset($_COOKIE[$this->httpOnlyPrefix.$this->refreshTokenCookieName]) ){
			// only refresh cookie!
			// init tokenRefresh!
			$error = 'No Tokencookie, but found a refreshCookie!';
    		throw new Exception($error,408);
		}
		
		if(isset($_COOKIE[$this->httpOnlyPrefix.$this->tokenCookieName]) && isset($_COOKIE[$this->httpOnlyPrefix.$this->refreshTokenCookieName]) ){
			// both cookies found!
			
			return true;
			#if($this->jwt_public_key==false){
			#	return true;
			#}else{
			#	return $this->verifyJWT($_COOKIE[$httpOnlyPrefix.$tokenCookieName],$this->jwt_public_key);
			#}
		}
		
	}
	
	
	public function getRefreshToken(){		
		
		return $_COOKIE[$this->httpOnlyPrefix.$this->refreshTokenCookieName];
	}
	
	
	
	
	private function setNewCookies($tokenResponse){
		
		
		$this->accessToken =$tokenResponse['access_token'];
		
		$this->setHttpOnlyCookie($httpOnlyPrefix.$tokenCookieName ,$tokenResponse['access_token'],$this->payload->exp);
		
		$this->ssid_expires = $this->payload->exp;
		
		$this->setCookie($tokenCookieName,$tokenResponse['access_token'],$this->payload->exp);
		
		$this->sid_expires = $this->payload->exp;
		
		$this->setCookie($expireCookieName,$this->payload->exp,$this->payload->exp);

		$this->refreshToken =$tokenResponse['refresh_token'];
		
		$this->setHttpOnlyCookie($httpOnlyPrefix.$refreshTokenCookieName ,$tokenResponse['refresh_token'],time()+2419200);
		
		$this->setHttpOnlyCookie($httpOnlyPrefix.$expireCookieName ,time()+2419200,time()+2419200);
		
		$this->srid_expires = time()+2419200;
		
	}
		
	private function setCookie($name,$value,$expire=0,$path=""){
		$httponly = false;
		$secure = true;
		$domain = $this->cookiedomain;
		
		setcookie ( $name ,  $value  ,  $expire , $path  ,  $domain , $secure ,  $httponly  );
	}
	
	private function setHttpOnlyCookie($name,$value,$expire,$path=""){
		$httponly = true;
		$secure = true;
		$domain = $this->cookiedomain;
		
		setcookie ( $name ,  $value  ,  $expire , $path  ,  $domain , $secure ,  $httponly  );
	}
	
	
	
	
	
	
	private function verifyJWT($jwt_access_token,$jwt_public_key){
		
		//$token = json_decode($curlResponse);

		//$jwt_access_token = $token['access_token'];

		$separator = '.';

		if (2 !== substr_count($jwt_access_token, $separator, $algo=OPENSSL_ALGO_SHA256)) {
			//throw new \Exception("Incorrect access token format");
			return false;
		}

		list($header, $payload, $signature) = explode($separator, $jwt_access_token);

		$decoded_signature = base64_decode(str_replace(array('-', '_'), array('+', '/'), $signature));

		// The header and payload are signed together
		$payload_to_verify = utf8_decode($header . $separator . $payload);

		// however you want to load your public key
		$public_key = file_get_contents($jwt_public_key);

		// default is SHA256
		$verified = openssl_verify($payload_to_verify, $decoded_signature, $public_key, $algo);

		if ($verified !== 1) {
			//throw new \Exception("Cannot verify signature");
			return false;
		}

		// output the JWT Access Token payload
		return json_decode(base64_decode($payload));
		
		
	}
}