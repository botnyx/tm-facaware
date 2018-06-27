<?php 

#working version

namespace botnyx\tmfacaware;

use ArrayAccess;
use Slim\Http\Request;
use Slim\Http\Response;

// \botnyx\tmfacaware\idpconn


class idpconn {
	
	var $idpServer;
	var $client_id;
	var $client_secret;
	
	var $tokenEndpoint		= '/token';
	var $authorizeEndpoint	= '/authorize';
	
	var $userAgent = 'trustmaster/1.0';
	
	var $debug 			= false;
	var $timeout 		= 5;
	var $connecttimeout = 3.14;
	
		
	var $accessToken; 
	
	var $clientTokenFile = '../src/clienttoken.json.tmp';
	
	function __construct($server,$clientid,$clientsecret,$jwt_pub_key=false){

		$this->client_id 	= $clientid;
		$this->client_secret= $clientsecret;
		$this->idpServer = $server;
		
		$this->tokenCache();
		
	}
	
	
	private function tokenCache(){
		#echo "<pre>";
		#echo "tokencache()\n";
		// check if token in cache.
		if(file_exists($this->clientTokenFile)){
			
			// 
			#echo "EXIST\n";
			$handle = fopen($this->clientTokenFile, "r");
			$token = json_decode(fread($handle, filesize($this->clientTokenFile)),true);
			fclose($handle);
			
			#echo (time()-filemtime($this->clientTokenFile))."\n";
			#echo ($token['data']['expires_in']-120)."\n";
			
			if(  (time()-filemtime($this->clientTokenFile)) > ($token['data']['expires_in']-120) ){
				// Get token.
				error_log("idpconn - renew token.");
				$token = $this->getTokenByClientCredentials();
				$handle = fopen($this->clientTokenFile, "w");
				fwrite($handle, json_encode($token) ) ;
				fclose($handle);
			}
				
			
		}else{
			// Get token.
			#echo "NEW\n";
			$token = $this->getTokenByClientCredentials();
			$handle = fopen($this->clientTokenFile, "w");
			fwrite($handle, json_encode($token) ) ;
			fclose($handle);
		}	
		
		
		
		#print_r($token);
		#die("xxxxxx");
		// 
		$this->accessToken = $token['data']['access_token'];
		
	}
	
	
	
	
	
	
	
	
	
	
	
	
	public function getTokenByAuthCode ($authorizationCode){
		$response  = $this->exchange_authorization_code_for_token($authorizationCode);
		return $this->format($response);
	}
	
	public function getTokenByRefreshToken (){
		$response  = $this->exchange_refreshtoken_for_token($refreshToken);
		return $this->format($response);
	}
	
	public function getTokenByClientCredentials (){
		
		$response  = $this->client_credentials();
		
		#echo "<pre> getTokenByClientCredentials()\n";
	
		#echo $this->idpServer.$this->tokenEndpoint."\n";
		
		return $this->format($response);
	}
	
	public function getTokenByUserCredentials ($user,$pass){
		$response  = $this->user_credentials($user,$pass);
		return $response;
		#var_dump($response);
		#die();
		#
		#return $this->format($response);
	}
	
	
	
	public function getAuthorizationCodeFromRedirect ($authorized,$client_id,$user_id,$idpServer,$idpauthorizeEndpoint){
		// $idpServer;$idpauthorizeEndpoint;
		var_dump($getAuthorizationCodeFromRedirect);
		//if(	$authorized==true){ $authorized='yes'; }else{$authorized='no';}
		$response = $this->get_authorization_code_from_redirect($authorized,$client_id,$user_id,$idpServer,$idpauthorizeEndpoint);
		return $this->format($response);
	}
		
	public function getLink($redir_url){
		return $this->authorization_code_link($redir_url);
		
	}
	
	
	 
	public function format ($response){
		
		if(is_array($response)){
			//print_r($response);
			return $response;
		}
		// Check if response is json, and decode it if it is.
		$respHeaders = $response->getHeaders();
		//
		if( array_key_exists('Content-Type',$respHeaders) && in_array("application/json",$respHeaders['Content-Type']) ){
			$res = json_decode($response->getBody()->getContents(),true);
		}else{
			$res = $response->getBody()->getContents();
		}
		$out = array("code"=>$response->getStatusCode(),"data"=>$res);
		return $out;
	}
	
	
	private function user_credentials($user,$pass){
		// grant_type=
		// $ curl -u TestClient:TestSecret https://api.mysite.com/token -d 'grant_type=password&username=bshaffer&password=brent123'
		
		$client = new \GuzzleHttp\Client();
		
		$options = [
			'timeout' => $this->timeout,
			'connect_timeout' => $this->connecttimeout,
			'allow_redirects'=>[
				'protocols'=>['https']
			],
			'http_errors' => false,
			'auth' => [
				$this->client_id, $this->client_secret
			],
			'headers' => [
        		'Accept'     => 'application/json',
				'User-Agent' => 'trustmaster/1.0'
			],
			'form_params' => [
				'grant_type' => 'password',
				'username' => $user,
				'password' => $pass
			]
		];
		
		
		$response =  $client->request('POST', $this->idpServer.$this->tokenEndpoint, $options);
		return $this->format($response);
	}
	
	private function authorization_code_link($redir_url){
		// grant_type=
		//$redir = "https://myredirecturi.com/callback";
		$url = $this->idpServer.$this->tokenEndpoint."?response_type=code&client_id=".$this->client_id."&redirect_uri=".$redir_url;
		
		return $url;
		
	}
		
	private function exchange_authorization_code_for_token($authorizationCode){
		// grant_type=
		// $ curl -u TestClient:TestSecret https://api.mysite.com/token -d 'grant_type=authorization_code&code=xyz'
		
		//curl -u TestClient:TestSecret https://api.mysite.com/token -d 'grant_type=authorization_code&code=xyz'
		
		$client = new \GuzzleHttp\Client();
		//die("x");
		#echo "<pre>";
		$options = [
			'timeout' => $this->timeout,
			'connect_timeout' => $this->connecttimeout,
			'allow_redirects'=>[
				'protocols'=>['https']
			],
			'debug' => $this->debug,
			'http_errors' => false,
			'auth' => [
				$this->client_id, $this->client_secret
			],
			'form_params' => [
				'grant_type' => 'authorization_code',
				'code' =>$authorizationCode
			],
			'headers' => [
        		'Accept'     => 'application/json',
				'User-Agent' => 'trustmaster/1.0'
			]
		];
		
		return $client->request('POST', $this->idpServer.$this->tokenEndpoint, $options);
	}
		
	private function client_credentials(){
		// grant_type=client_credentials
		// $ curl -u TestClient:TestSecret https://api.mysite.com/token -d 'grant_type=client_credentials'
		
		$client = new \GuzzleHttp\Client();
		
		$options = [
			'timeout' => $this->timeout,
			'form_params'=>[
				'grant_type'=>'client_credentials'
			],
			'http_errors' => false,
			'auth' => [
				$this->client_id, $this->client_secret
			],
			'connect_timeout' => $this->connecttimeout,
			'allow_redirects'=>[
				'protocols'=>['https']
			],
			'debug' =>  $this->debug,
			
			'headers' => [
				'Content-Type'=>'application/x-www-form-urlencoded',
        		'User-Agent' => $this->userAgent
			]
		];
		
		return $client->request('POST', $this->idpServer.$this->tokenEndpoint, $options );
		
	}
	
	private function exchange_refreshtoken_for_token($refreshToken){
		// grant_type=refresh_token
		// refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
		// $ curl -u TestClient:TestSecret https://api.mysite.com/token -d 'grant_type=password&username=bshaffer&password=brent123'
		$client = new \GuzzleHttp\Client();
		
		$options = [
			'timeout' => $this->timeout,
			'connect_timeout' => $this->connecttimeout,
			'debug' => $this->debug,
			'http_errors' => false,
			'auth' => [
				$this->client_id, $this->client_secret
			],
			'form_params' => [
				'grant_type' => 'refresh_token',
				'refresh_token' => $refreshToken
			],
			'headers' => [
				'Accept'     => 'application/json',
        		'User-Agent' => $this->userAgent
			]
		];
		
		return $client->request('POST', $this->idpServer.$this->tokenEndpoint,$options );
	}
	
	
	/*
		this function is 'special'
	*/
	private function get_authorization_code_from_redirect($authorized,$client_id,$user_id,$idpServer,$idpauthorizeEndpoint){
		
		// grant_type=
		// https://api.mysite.com/authorize?response_type=code&client_id=TestClient&redirect_uri=https://myredirecturi.com/cb
		// A successful authorization will pass the client the authorization code in the URL via the supplied redirect_uri:
		// https://myredirecturi.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
		// Once this is done, a token can be requested using the authorization code.  exchange_authorization_code_for_token()
		
		//POST=>
		// https://idp.trustmaster.nl/authorize?response_type=code&client_id=jerryhopper.com&state=1528031546&user_id=1234
		$state = time();
		
		$url = $idpServer.$idpauthorizeEndpoint."?response_type=code&client_id=".$client_id."&state=".$state."&user_id=".$user_id;
		#echo "receiveAuthCode posts :\n";
		#echo $url."\n";
		$client = new \GuzzleHttp\Client();
		#echo "<pre>";
		$options = [
			'timeout' => $this->timeout,
			'connect_timeout' => $this->connecttimeout,
			
			'http_errors' => false,
			'form_params' => [
				'authorized' => $authorized
			],
			'allow_redirects' => false,
			'headers' => [
        		'User-Agent' => 'trustmaster/1.0',
				'Accept'     => 'application/json',
				'Authorization'=> 'Bearer '.$this->accessToken
			],
		];
		
		echo "<pre>";
		var_dump($options);
		var_dump($url);
		var_dump($authorized);
		$response = $client->request('POST', $url , $options);
		
		
		if($response->getStatusCode()==302){
			
			
			
			$result_array['url']=$response->getHeader('Location')[0];
			
			$status = array('code'=>$response->getStatusCode(),"data"=>$result_array);
		}else{
			$status = array('code'=>$response->getStatusCode(),"data"=>json_decode($response->getBody()->getContents()));
			
		}
		return $status;	
		
		
		
		
		
		
	}
	
	
	
	
	
	//   $this->idp->post('/oauthserver/users',['email' => $email_dc,'password' => $password_dc]);
	
	private function createClient(){
		$client = new \GuzzleHttp\Client([
			// Base URI is used with relative requests
			'base_uri' => $this->idpServer,
			// You can set any number of default request options.
			'headers' => [
        		'User-Agent' => 'trustmaster/1.0',
				'Accept'     => 'application/json',
				'Authorization'=> 'Bearer '.$this->accessToken
			],
			'connect_timeout' => 3.14,
			'timeout' => 3.14,
			'allow_redirects'=>[
				'protocols'=>['https']	
			],
			'http_errors' => false
		]);
		
		return $client;
	}
	
	public function post($path,$json=array()){
		error_log("IDP POST!");
		$options = ['json' => $json];
		$response = $this->call('POST',$path,$options);
		return $this->format($response);
		#return array("code"=>$response->getStatusCode(),"data"=>$response->getBody()->getContents());
	}
	
	
	private function call($type='GET',$path,$options){
		
		$client = $this->createClient();
		$response = $client->request(strtoupper($type), $this->idpServer.$path,$options);
		
		
		#error_log($response->getStatusCode()." call(".$type.",".$path.")");
		
		
		
		if($response->getStatusCode()!=200){ 
			throw new \Exception($response->getBody()->getContents(),$response->getStatusCode());
	   	}
		return $response;
	}
	
	
	
	
	
}