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
	var $localeCookieName		= "LOC";
	var $zoneinfoCookieName		= "TZ";
	
	function __construct($jwt_public_key = false){
		
		$this->jwt_public_key = $jwt_public_key;
		
		$this->cookiedomain = $_SERVER['HTTP_HOST'];
		$this->requestedUrl = $_SERVER['SCRIPT_URI']."?".$_SERVER['QUERY_STRING'];
		
	}
	
	
	public function verifyCookies(){
		
		if(!isset($_COOKIE[$this->httpOnlyPrefix.$this->tokenCookieName]) && !isset($_COOKIE[$this->httpOnlyPrefix.$refreshTokenCookieName]) ){
			// no valid cookie!
			$error = 'No cookies found!';
    		throw new \Exception($error,404);
		}
		
		if(!isset($_COOKIE[$this->httpOnlyPrefix.$this->tokenCookieName]) && isset($_COOKIE[$this->httpOnlyPrefix.$this->refreshTokenCookieName]) ){
			// only refresh cookie!
			// init tokenRefresh!
			$error = 'No Tokencookie, but found a refreshCookie!';
    		throw new \Exception($error,408);
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
	
	public function getAccessToken(){		
		
		return $_COOKIE[$this->httpOnlyPrefix.$this->tokenCookieName];
	}
	
	public function getRefreshToken(){		
		
		return $_COOKIE[$this->httpOnlyPrefix.$this->refreshTokenCookieName];
	}
	
	
	
	
	
	
	public function setNewCookies($tokenResponse,$decodedToken,$refreshTokenLifeTime=2419200){
		
		#print_r($tokenResponse);
		#print_r($decodedToken);
		
		$this->accessToken =$tokenResponse['access_token'];
		
		// SSID
		$this->setHttpOnlyCookie($this->httpOnlyPrefix.$this->tokenCookieName ,$tokenResponse['access_token'],$decodedToken->exp);
		
		$this->ssid_expires = $decodedToken->exp;
		// SID
		$this->setCookie($this->tokenCookieName,$tokenResponse['access_token'],$decodedToken->exp);
		
		$this->sid_expires = $decodedToken->exp;
		
		$this->setCookie($this->expireCookieName,$decodedToken->exp,$decodedToken->exp);
		
		
		$this->setCookie($this->localeCookieName,$decodedToken->locale);
		
		$this->setCookie($this->zoneinfoCookieName,$decodedToken->zoneinfo);

		$this->refreshToken =$tokenResponse['refresh_token'];
		
		$this->setHttpOnlyCookie($this->httpOnlyPrefix.$this->refreshTokenCookieName ,$tokenResponse['refresh_token'],time()+$refreshTokenLifeTime);
		
		$this->setHttpOnlyCookie($this->httpOnlyPrefix.$this->expireCookieName ,time()+$refreshTokenLifeTime,time()+$refreshTokenLifeTime);
		$this->setHttpOnlyCookie($this->httpOnlyPrefix.$this->expireCookieName ,time()+$refreshTokenLifeTime,time()+$refreshTokenLifeTime);
		
		$this->srid_expires = time()+$refreshTokenLifeTime;
		
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
