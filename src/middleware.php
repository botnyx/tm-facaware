<?php



namespace botnyx\tmfacaware;

use ArrayAccess;
use Slim\Http\Request;
use Slim\Http\Response;



class middleware {
	
	
	var $noredir = false;
	var $refreshTokenLifeTime = 2419200;
	
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
			//echo "COOKIE EXCEPTION:".$e->getCode()."<br>";
			/*  404 No cookies found or 408 No Tokencookie, but found a refreshCookie! 	*/
			if($e->getCode()==408){
				// only refreshcookie
				// get the refreshtoken from cookie.
				
				$rtoken = $this->cookieMan->getRefreshToken();
				#echo $rtoken;
				
				// exchange refreshtoken for new token.
				$newtoken = $this->idp->getTokenByRefreshToken($rtoken);
				#print_r($newtoken);
				$redirectUrl = "https://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
				if($newtoken['code']==200){

					if(!$this->jwt->decode($newtoken['data']['access_token']) ){
						echo "Something terrible happened, jwt didnt pass verification!\n";
						var_dump($r['data']['access_token']);
						die();
					}

					//echo "JWT decode success!";
					// get the payload.
					$result = $this->jwt->getPayload();

					// set the new token
					// setNewCookies($tokenResponse,$decodedToken
					$this->cookieMan->setNewCookies($newtoken['data'],$this->jwt->getPayload(),$this->refreshTokenLifeTime);
					if($this->noredir ){
						echo "<a href='$redirectUrl'>REDIR!</a>";
						die();
					}
					return $response->withRedirect($redirectUrl, 301);
				}else{
					$this->cookieMan->delSIDCookies();
					
					
					if($this->noredir ){
						echo "<pre>";
						var_dump( $newtoken['data']['error_description'] );
						echo "<a href='$redirectUrl'>REDIR!</a>";
						die();
					}
					return $response->withRedirect($redirectUrl, 301);
					die();
					
				}
				//$isAuthenticated = $this->cookieMan->verifyCookies();
				
			}
			if($e->getCode()==404){
				// no cookies
				
			}
		}
		/* var $isAuthenticated is set. */
		$this->userAccessToken = $this->cookieMan->getAccessToken();
		
		/************************************************************************
		
				CALLBACK URL
		
		************************************************************************/
		if( $url_path==$this->callback_uri){
			error_log(__LINE__." ".__FILE__ );
			$response = $this->route_Callback($request,$response);
			return $response;
		}

		/***********************************************************************
		
				TOKEN URL
		
		************************************************************************/
		if( $url_path==$this->token_uri){
			
			#echo "TOKEN";
			#die();
			// This is the Token URI. we proxy this request to our internal IDP.
			$response = $next($request, $response);
			return $response;
		}
		
		/************************************************************************
		
				AUTHORIZE URL
		
		************************************************************************/
		if( $url_path==$this->authorize_uri){
			
			return $this->route_Authorize($isAuthenticated,$request,$response);

		}
		
		/************************************************************************
		
				Any url that needs AUTH, but not anonymous
		
		************************************************************************/
		
		if( !in_array('anon',$this->scopes) && !$isAuthenticated && $url_path!=$this->authorize_uri ){
			// Anonymous access is not allowed.
			// in a normal oauth situation we should be redirected to the authorisation endpoint.
			error_log("middleware: "."ANON NOT ALLOWED!");
			
			
			$redirectUrl = $_SERVER['SCRIPT_URI'];
			$redirectUrl = "https://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
			echo "PROTECTED URL : ".$redirectUrl."\n";
			$_SESSION['lastUrl']= $redirectUrl;
			
			//https://accounts.trustmaster.nl
			
			
			$endpoint = $this->server."/authorize?response_type=code&client_id=". $this->client_id."&state=". time()."&redirect_uri=". $redirectUrl;
			
			$this->idp->getLink($redirectUrl);
			
			if($this->noredir ){
				echo "REDIRECT:\n<a href='".$endpoint."'>".$endpoint."</a>";
				die();
			}
			return $response->withRedirect($endpoint, 302);
		}
		
		// Add the tokens to the request as attribute.
		$request = $request->withAttribute("access_token",$this->cookieMan->getAccessToken());
		$request = $request->withAttribute("refresh_token",$this->cookieMan->getAccessToken());
		
		
		$response = $next($request, $response);
		
		
        return $response;	
	}
	
	private function checkGrants($client,$user,$scopes){
		//$checkGrants();
		
		
		return false;
	}

	private function route_Authorize_authenticated($request,$response){
		#echo "You are authenticated!\n";
		$allGetVars 	= $request->getQueryParams();
		$allPostPutVars = $request->getParsedBody();
		$method 		= $request->getMethod();

		$decodedJWT = $this->jwt->decode($this->userAccessToken);
		
		
		
		if($decodedJWT==false){
			// JWT token is invalid!
			// 
			
		}
		
		
		$alreadyGranted = $this->checkGrants( $decodedJWT->aud, $decodedJWT->sub, $decodedJWT->scope );
		
		
		
		/*
			TODO: authorization administration

			if user already granted for the exact scopes before, we need to skip the 'question' to authorize.


			$allGetVars['client_id']


			$decodedJWT->scope scopes

			$decodedJWT->aud  aud = accounts.

			$decodedJWT->sub  user-123@trustmaster.nl



			client_id:user_id  scope yes

		if(){

		}

		*/

		
		

		//$alreadyGranted = false;
		//&& $alreadyGranted==true
		if( $method=='GET' &&  $alreadyGranted == false ){
			/* method = GET,  present authorization screen for this client */
			#echo "present Grant Auth screen\n";

			##############################################################################
			return $this->container['view']->render($response, 'base-layout.phtml', [
				'screen' => 'authorize',
				'data'=>array('client_id'=>$allGetVars['client_id'],'jwt'=>$decodedJWT),
				'error'=>''
			]);
			##############################################################################

		}



		#echo "receive GrantScreen data via post.<br>";
		#print_r($allPostPutVars);


		//$decodedJWT = $this->jwt->decode($this->userAccessToken);

		$decodedJWT->sub;
		$decodedJWT->exp;
		$decodedJWT->scope;
		//getAccessToken();
		#echo "<pre>";
		#print_r($allGetVars);
		#echo "</pre>";
		#echo "<pre>";
		#print_r($decodedJWT);
		#echo "</pre>";
		#var_dump( $this->authorize_uri);
		#var_dump( $this->server);

		if($alreadyGranted){
			$userAuthorizationResponse='yes';
		}else{
			$userAuthorizationResponse = $allPostPutVars['authorized'];
		}
		#var_dump($method);
		#var_dump($alreadyGranted);
		#var_dump($userAuthorizationResponse);
		#var_dump($allPostPutVars);
		
		

		$R = $this->idp->getAuthorizationCodeFromRedirect(	strtolower(	$userAuthorizationResponse ),
																		   $allGetVars['client_id'],
																		   $decodedJWT->sub,
																		   $this->server,
																		   $this->authorize_uri);
		
		
		
		#die("UuUuU");
		
		
		#die();
		if($R['code']==302){
			// YES we have a redirect!
			$R['data'];
			#$R['data']['state'];
			$R['data']['url'];

			$parsedUrl = parse_url($R['data']['url']);
			#var_dump($parsedUrl);


			parse_str($parsedUrl['query'], $idp_response);
			#var_dump($idp_response);

			$uri = $R['data']['url']."&redirect_uri=".$allGetVars['redirect_uri'];

			//$this->noredir = true;
			if($this->noredir ){
				echo "<a href='$uri'>REDIR!</a>";
				die();
			}
			//$response = \Slim\Http\Response();

			###############################################################################
			return $response->withRedirect($uri, 301);
			###############################################################################

		}else{
			error_log("idp->getAuthorizationCodeFromRedirect returns: ".$R['code']);
			echo "\n--->".$this->server;
			echo "\n>".$this->authorize_uri;
			echo "idp->getAuthorizationCodeFromRedirect returns: ".$R['code'];
			echo "<pre>";
			print_r($R);
			echo "</pre>";
			
			$R['data']['error'];
			$R['data']['error_description'];


		}
		//print_r($R);
		die();



	}
	
	private function route_Authorize_unauthenticated($request,$response){
		if($this->noredir ) echo "<pre>You are NOT loggedin!\n";
		
		$allPostPutVars = $request->getParsedBody();
		$allGetVars = $request->getQueryParams();
		$method 	= $request->getMethod();
		
		if($method=='POST'){
			//$authorizeRoute->login();
			echo "Referred via :".$allGetVars['redirect_uri'] ."\n";
			
			
			// request token from IDP server.
			$r = $this->idp->getTokenByUserCredentials( $allPostPutVars['TMinputEmail']."@trustmaster.nl",$allPostPutVars['TMinputPassword']);
			
			
			
			
			if($r['code']==200){
				// Response OK, we have a token now.
				// Doublecheck by verifying the the JWT token. 
				if(!$this->jwt->decode($r['data']['access_token']) ){
					echo "Something terrible happened, jwt didnt pass verification!\n";
					var_dump($r['data']['access_token']);
					die();
				}
				
				//echo "JWT decode success!";
				// get the payload.
				$result = $this->jwt->getPayload();
				
				//echo "We are authenticated! set cookies!\n";
				
				
				#setNewCookies();
				$this->cookieMan->setNewCookies($r['data'],$this->jwt->getPayload(),$this->refreshTokenLifeTime);

				if($this->noredir ){
					echo "\nREDIRECT:\n<a href='https://accounts.trustmaster.nl".$_SERVER['REQUEST_URI']."'>".$_SERVER['REQUEST_URI']."</a>";
					die();
				}
				
				return $response->withRedirect($_SERVER['REQUEST_URI'], 301);

				#var_dump($_SERVER['REQUEST_URI']);
				#print_r($r);
				#die();
			}else{
				if($this->noredir )echo "present LOGIN screen\n";
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
			error_log("Authenticated.");
			return $this->route_Authorize_authenticated($request,$response);
		}
		else
		{
			error_log("Not authenticated.");
			return $this->route_Authorize_unauthenticated($request,$response);
		}
	}
	
	
	
	private function route_Callback($request,$response){
		$allGetVars 	= $request->getQueryParams();
		$allGetVars['code'];
		
		$result = $this->idp->getTokenByAuthCode($allGetVars['code']);
		
		#echo "<pre>";		
		#var_dump($this->idp);
		#var_dump($result);
		
		if($result['code']==200){
			// Response OK, we have a token now.
			// Doublecheck by verifying the the JWT token. 
			if(!$this->jwt->decode($result['data']['access_token']) ){
				echo "Something terrible happened, jwt didnt pass verification!\n";
				var_dump($result);
					die();
				die();
			}
			//echo "JWT decode success!";
			// get the payload.
			//$this->jwt->getPayload();
			//cho "We are authenticated! set cookies!\n";

			#setNewCookies();
			$this->cookieMan->setNewCookies($result['data'],$this->jwt->getPayload(),$this->refreshTokenLifeTime);
			
			
			if($this->noredir ){
				echo "\nREDIRECT:\n<a href='".$allGetVars['redirect_uri']."'>".$allGetVars['redirect_uri']."</a>";
				die();
			}

			return $response->withRedirect($allGetVars['redirect_uri'], 301);

			#var_dump($_SERVER['REQUEST_URI']);
			#print_r($r);
			#die();
		}else{
			if($this->noredir )echo "show Callback error screen\n";
			echo "<pre>";		
			//var_dump($this->idp);
			var_dump($result);
			
			
			
			return $this->container['view']->render($response, 'base-layout.phtml', [
				'screen' => 'callbackerror',
				'error'=>$allGetVars
			]);	
		}
			
		
		
		
		
		print_r($r);
		echo "route_Callback";
		die();
		if($this->noredir){
			echo "<a href='".$allUrlVars['redirect_uri']."'>".$allUrlVars['redirect_uri']."</a>";
			die();
		}
		return $response->withRedirect($allUrlVars['redirect_uri'], 302);
			
	}
	
		
	
	
    private function validateContainer($container)
    {
        if (is_a($container, ArrayAccess::class)) {
            return $container;
        }

        if (method_exists($container, 'set')) {
            return $container;
        }

        throw new \InvalidArgumentException("\$container does not implement ArrayAccess or contain a 'set' method");
    }
	
	
	 /**
     * Helper method to set the token value in the container instance.
     *
     * @param array $token The token from the incoming request.
     *
     * @return void
     */
    private function setToken(array $token)
    {
        if (is_a($this->container, '\\ArrayAccess')) {
            $this->container['token'] = $token;
            return;
        }

        $this->container->set('token', $token);
    }
	
	/**
     * Returns a callable function to be used as a authorization middleware with a specified scope.
     *
     * @param array $scopes Scopes require for authorization.
     *
     * @return Authorization
     */
    public function withRequiredScope(array $scopes)
    {
        $clone = clone $this;
        $clone->scopes = $clone->formatScopes($scopes);
        return $clone;
    }
    /**
     * Helper method to ensure given scopes are formatted properly.
     *
     * @param array $scopes Scopes required for authorization.
     *
     * @return array The formatted scopes array.
     */
    private function formatScopes(array $scopes)
    {
        if (empty($scopes)) {
            return [null]; //use at least 1 null scope
        }
        array_walk(
            $scopes,
            function (&$scope) {
                if (is_array($scope)) {
                    $scope = implode(' ', $scope);
                }
            }
        );
        return $scopes;
    }	


	
	
	
}