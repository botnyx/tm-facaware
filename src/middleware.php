<?php



namespace botnyx\tmfacaware;

use ArrayAccess;
use Slim\Http\Request;
use Slim\Http\Response;



class middleware {
	
	function __construct($settings,$container){
		
		
		$this->server 			=  $settings->idp_server;
		$this->client_id 		=  $settings->idp_clientid;
		$this->client_secret	=  $settings->idp_clientsecret;
		$this->jwt_public_key 	=  $settings->idp_public_key;
		
		$this->token_uri 		=  $settings->idp_token_uri;
		$this->authorize_uri 	=  $settings->idp_authorize_uri;
		$this->callback_uri		=  $settings->local_callback_uri;
		
		
		if( isset($settings->facade)){
			error_log("ARE YOU SURE THIS IS THE OAUTH FACADE?");
			//echo "ARE YOU SURE THIS IS THE OAUTH FACADE?";
		}
		
		if( isset($settings->facade->idp_server)){
			$this->facade_idp_server = $settings->facade->idp_server;
		}else{
			$this->facade_idp_server = $settings->idp_server;
		}
		
		if( isset($settings->facade->idp_token_uri)){
			$this->facade_idp_token_uri = $settings->facade->idp_token_uri;
		}else{
			$this->facade_idp_token_uri = $settings->idp_token_uri;
		}
		
		if( isset($settings->facade->idp_authorize_uri)){
			$this->facade_idp_authorize_uri = $settings->facade->idp_authorize_uri;
		}else{
			$this->facade_idp_authorize_uri = $settings->idp_authorize_uri;
		}
		
		
		
		#var_dump( isset($settings->facade->idp_servers));
		#die();
		
		/*
		$a['client_id'];
		$a['client_secret'];
		$a['jwt_public_key'];
		$a['idp_server'];
		$a['authorize_uri'];
		$a['callback_uri'];
		$a['token_uri'];
		*/
		
		#$this->server	=$server;
		#$this->client_id=$clientid;
		#$this->client_secret=$clientsecret;
		#$this->jwt_public_key=$jwt_public_key;
		
		$this->container = $this->validateContainer($container);
		
		// $this->idp = new \botnyx\tmfacaware\idpconn();
		
		$this->jwt = new \botnyx\tmfacaware\jwtdecode($this->jwt_public_key);

		
		
		$this->idp = new \botnyx\tmfacaware\idpconn($this->server,$this->client_id,$this->client_secret);
		
		
		// start a new cookiemanager.
		$this->cookieMan = new \botnyx\tmfacaware\cookiemanager($this->server,$this->client_id,$this->client_secret,$this->jwt_public_key);
	}
	
	
	/**
     * Example middleware invokable class
     *
     * @param  \Psr\Http\Message\ServerRequestInterface $request  PSR7 request
     * @param  \Psr\Http\Message\ResponseInterface      $response PSR7 response
     * @param  callable                                 $next     Next middleware
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke($request, $response, $next)
    {
		// 
		$allGetVars 	= $request->getQueryParams();
		$allPostPutVars = $request->getParsedBody();
		$allUrlVars 	= $request->getQueryParams();
		//
		$url_path 	= $request->getUri()->getPath();
		$method 	= $request->getMethod();
		
		/* Authentification check */
		$isAuthenticated = false;
		try{
			$isAuthenticated = $this->cookieMan->verifyCookies();
		}catch(\Exception $e){
			/*  404 No cookies found or 408 No Tokencookie, but found a refreshCookie! 	*/
			if($e->getCode()==408){
				// only refreshcookie
				// get the refreshtoken from cookie.
				$rtoken = $this->cookieMan->getRefreshToken();
				// exchange refreshtoken for new token.
				$newtoken = $this->idp->exchange_refresh_token_for_token($rtoken);
				
				// set the new token
				//$this->cookieMan->setNewCookies($newtoken);
				//$isAuthenticated = $this->cookieMan->verifyCookies();
				
			}
			
			if($e->getCode()==404){
				// no cookies
				
			}
		}
		/* var $isAuthenticated is set. */
		
		
		
		
		
		/************************************************************************
		
				CALLBACK URL
		
		************************************************************************/
		if( $url_path==$this->callback){
			$this->route_Callback();
			return $response;
		}

		/***********************************************************************
		
				TOKEN URL
		
		************************************************************************/
		if( $url_path==$this->token_uri){
			// This is the Token URI. we proxy this request to our internal IDP.
			$response = $next($request, $response);
			return $response;
		}
		
		
		
		/************************************************************************
		
				AUTHORIZE URL
		
		************************************************************************/
		if( $url_path==$this->authorize_uri){
			return $this->route_Authorize($isAuthenticated,$response);

		}
		
		
		
		
		
		/************************************************************************
		
				Any url that needs AUTH, but not anonymous
		
		************************************************************************/
		if( !in_array('anon',$this->scopes) && !$isAuthenticated && $url_path!=$this->authorize_uri ){
			// Anonymous access is not allowed.
			// in a normal oauth situation we should be redirected to the authorisation endpoint.
			error_log("middleware: "."ANON NOT ALLOWED!");
			
			
			$redirectUrl = $_SERVER['SCRIPT_URI'];
			
			echo "PROTECTED URL : ".$redirectUrl."\n";
			$_SESSION['lastUrl']= $redirectUrl;
			
			//https://accounts.trustmaster.nl
			
			
			$endpoint = $this->facade_idp_server."/authorize?response_type=code&client_id=".$this->client_id."&state=".time()."&redirect_uri=".$redirectUrl;
			$this->idp->getLink($redir_url);
			
			if($this->noredir ){
				echo "REDIRECT:\n<a href='".$endpoint."'>".$endpoint."</a>";
				die();
			}
			return $response->withRedirect($endpoint, 302);
		}
		
		
		
		
		
			
		$response = $next($request, $response);
		
		
        return $response;	
	}
	
	

	
	private function route_Authorize_authorized($request,$response){
		echo "You are authenticated!\n";
		$allGetVars = $request->getQueryParams();
		$method 	= $request->getMethod();

		if($method!='POST'){
			echo "present Grant Auth screen\n";
			return $this->container['view']->render($response, 'base-layout.phtml', [
				'screen' => 'authorize',
				'data'=>array('client_id'=>$allGetVars['client_id']),
				'error'=>''
			]);	
		}else{
			echo "receive GrantScreen data via post.";
			print_r($allPostPutVars);



			#print_r($this->cookieMan);
			#$this->cookieMan->payload->aud

			$R = $this->idp->receiveAuthCode(strtolower($allPostPutVars['authorized']),$allGetVars['client_id'],$this->cookieMan->payload->sub);


			if($R['code']==302){
				// YES we have a redirect!
				$R['data']['code'];
				$R['data']['state'];
				$R['data']['url'];
				$parsedUrl = parse_url($R['data']['url']);
				var_dump($parsedUrl);


				parse_str($parsedUrl['query'], $idp_response);
				var_dump($idp_response);

				$uri = $R['data']['url']."&redirect_uri=".$allGetVars['redirect_uri'];

				if($this->noredir ){
					echo "<a href='$uri'>REDIR!</a>";
					die();
				}
				$response = \Slim\Http\Response();
				
				return $response->withRedirect($uri, 301);


			}else{
				$R['data']['error'];
				$R['data']['error_description'];


			}
			//print_r($R);
			die();





			die();
		}
	}
	
	
	private function route_Authorize_unauthorized($request,$response){
		echo "You are NOT loggedin!\n";
		echo "present LOGIN screen\n";
		$allGetVars = $request->getQueryParams();
		$method 	= $request->getMethod();
		
		echo $method."\n";
		if($method=='POST'){
			//$authorizeRoute->login();
			echo "Referred via :".$_SESSION['lastUrl']."\n";

			$r = $this->idp->oauthLogin($allPostPutVars['TMinputEmail']."@trustmaster.nl",$allPostPutVars['TMinputPassword']);
			if($r['code']==200){
				// OK!
				// Doublecheck by verifying the the JWT token. 
				if(!$this->cookieMan->verifyJWT($r['data']['access_token']) ){
					echo "Something terrible happened, jwt didnt pass verification!\n";
					die();
				}

				echo "We are authenticated! set cookies!\n";
				$this->cookieMan->setNewCookies($r['data']);

				if($this->noredir ){
					echo "\nREDIRECT:\n<a href='https://accounts.trustmaster.nl".$_SERVER['REQUEST_URI']."'>".$_SERVER['REQUEST_URI']."</a>";
					die();
				}
				
				return $response->withRedirect($_SERVER['REQUEST_URI'], 301);

				#var_dump($_SERVER['REQUEST_URI']);
				#print_r($r);
				#die();
			}else{
				// nok!
				return $this->container['view']->render($response, 'base-layout.phtml', [
					'screen' => 'signin',
					'error'=>$r
				]);	
			}




		}else{
			return $this->container['view']->render($response, 'base-layout.phtml', [
					'screen' => 'signin'
			]);	
		}

			//var_dump($method);

	}
	
	
	private function route_Authorize($isAuthenticated,$request,$response){
		#$allGetVars 	= $request->getQueryParams();
		#echo "middleware: "."We are at the AUTHORIZE URI\n";
		#echo "Referred via :".$allGetVars['redirect_uri']."\n";
		if($isAuthenticated){
			return $this->route_Authorize_authorized($request,$response);
		}
		else
		{
			return $this->route_Authorize_unauthorized($request,$response);
		}
	}
	
	
	
		
	
	
	
	
	
}