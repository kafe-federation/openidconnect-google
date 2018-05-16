<?php

use InoOicClient\Oic\Authorization;
use Zend\Http\Request;
use InoOicClient\Oic\Token\Request as TokenRequest;
use InoOicClient\Client\ClientInfo;
use InoOicClient\Oic\Token\Dispatcher;
use InoOicClient\Oic\UserInfo\Dispatcher as InfoDispatcher;
use InoOicClient\Oic\UserInfo\Request as InfoRequest;

//include('OAuth2.php');
// This class is not namespaced as simplesamlphp does not namespace its classes.

class sspmod_openidconnect_Auth_Source_Connect extends SimpleSAML_Auth_Source {

    /**
     * The client ID
     */
    protected $clientId;

    /**
     * The client secret.
     */
    protected $clientSecret;

    /**
     * The token endpoint.
     */
    protected $tokenEndpoint;

    /**
     * The user info endpoint.
     */
    protected $userInfoEndpoint;

    /**
     * The auth endpoint.
     */
    protected $authEndpoint;

    /**
     * The sslcapath for the Zend Http client.
     * @see http://framework.zend.com/manual/current/en/modules/zend.http.client.adapters.html
     */
    protected $sslcapath;

    /**
     * The scope we're requesting.
     */
    protected $scope = 'openid profile email';

    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct($info, $config) {
        /* Call the parent constructor first, as required by the interface. */
        parent::__construct($info, $config);

        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->tokenEndpoint = $config['token_endpoint'];
        $this->userInfoEndpoint = $config['user_info_endpoint'];
        $this->authEndpoint = $config['auth_endpoint'];
        $this->scope = $config['scope'];
    }

    /**
     * Return the config array.
     */
    protected function getConfig() {
        return array(
            'client_info' => array(
                'client_id' => $this->clientId,
                'redirect_uri' => SimpleSAML_Module::getModuleURL('openidconnect/resume.php'),
                'authorization_endpoint' => $this->authEndpoint,
                'token_endpoint' => $this->tokenEndpoint,
                'user_info_endpoint' => $this->userInfoEndpoint,
                'authentication_info' => array(
                    'method' => 'client_secret_post',
                    'params' => array(
                        'client_secret' => $this->clientSecret,
                    ),
                ),
            ),
        );
    }

    /**
     * Log in using an external authentication helper.
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(&$state) {
        $state['openidconnect:AuthID'] = $this->authId;
        $stateId = SimpleSAML_Auth_State::saveState($state, 'openidconnect:Connect');
        $info = $this->getConfig($stateId);

        SimpleSAML_Logger::error($this->scope);

        \SimpleSAML\Utils\HTTP::redirectTrustedURL($info["client_info"]["authorization_endpoint"], array(
            "client_id"     => $info["client_info"]["client_id"],
            "redirect_uri"  => $info["client_info"]["redirect_uri"],
            "response_type" => "code",
            "scope"         => $this->scope,
            "state"         => $stateId
        ));
    }

    /**
     *
     * Returns the equivalent of Apache's $_SERVER['REQUEST_URI'] variable.
     *
     * Because $_SERVER['REQUEST_URI'] is only available on Apache, we generate an equivalent using other environment variables.
     *
     * Taken from Drupal.
     * @see https://api.drupal.org/api/drupal/includes!bootstrap.inc/function/request_uri/7
     */
    public static function requesturi() {
        if (isset($_SERVER['REQUEST_URI'])) {
            $uri = $_SERVER['REQUEST_URI'];
        }
        else {
            if (isset($_SERVER['argv'])) {
                $uri = $_SERVER['SCRIPT_NAME'] . '?' . $_SERVER['argv'][0];
            }
            elseif (isset($_SERVER['QUERY_STRING'])) {
                $uri = $_SERVER['SCRIPT_NAME'] . '?' . $_SERVER['QUERY_STRING'];
            }
            else {
                $uri = $_SERVER['SCRIPT_NAME'];
            }
        }
        // Prevent multiple slashes to avoid cross site requests via the Form API.
        $uri = '/' . ltrim($uri, '/');

        return $uri;
    }

    /**
     * Map attributes from the response.
     */
    protected static function getAttributes($user) {
        // Map certain values to new keys but then return everything, in case
        // we need raw attributes from the server.
        foreach ($user as &$u) {
            // Wrap all values in an array, as SSP will expect.
            if (!is_array($u)) {
                $u = array($u);
            }
        }
	
        $mapped = array(
	    // displayName => urn:oid:2.5.4.3
	    // cn => urn:oid:2.16.840.1.113730.3.1.241  
	    // surname => urn:oid:2.5.4.4 
	    // givenName => urn:oid:2.5.4.42 
	    // eduPersonPrincipalName => urn:oid:1.3.6.1.4.1.5923.1.1.1.6
	    // mail => urn:oid:0.9.2342.19200300.100.1.3

	    'urn:oid:2.5.4.3'	=> $user['name'],
	    'urn:oid:2.16.840.1.113730.3.1.241' => $user['name'],
	    'urn:oid:2.5.4.4' => $user['family_name'],
	    'urn:oid:2.5.4.42' => $user['given_name'],
	    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6' => array(base64_encode(sha1($user['sub'][0]."gmail.com")) . "@kreonet.net"),
	    'urn:oid:0.9.2342.19200300.100.1.3' => $user['email'],
        );
        //return $mapped + $user;
        return $mapped;
    }

    /**
     * Resume authentication process.
     *
     * This function resumes the authentication process after the user has
     * entered his or her credentials.
     *
     * @param array &$state  The authentication state.
     */
    public static function resume() {
        $request = Request::fromString($_SERVER['REQUEST_METHOD'] . ' ' . self::requesturi());
        if (!$stateId = $request->getQuery('state')) {
            throw new SimpleSAML_Error_BadRequest('Missing "state" parameter.');
        }
        $state = SimpleSAML_Auth_State::loadState($stateId, 'openidconnect:Connect');
        
        $source = SimpleSAML_Auth_Source::getById($state['openidconnect:AuthID']);
        if ($source === NULL) {
            throw new SimpleSAML_Error_Exception('Could not find authentication source.');
        }
        
        if (! ($source instanceof self)) {
            throw new SimpleSAML_Error_Exception('Authentication source type changed.');
        }

        // The library has its own state manager but we're using SSP's.
        // We've already validated the state, so let's get the token.
        $tokenDispatcher = new Dispatcher();
        $tokenRequest = new TokenRequest();
        $clientInfo = new ClientInfo();

        $inf = reset($source->getConfig());
        $clientInfo->fromArray($inf);
        $tokenRequest->setClientInfo($clientInfo);
        $tokenRequest->setCode($request->getQuery('code'));
        $tokenRequest->setGrantType('authorization_code');

        //$tokenDispatcher->setOptions(['http_options' => ['sslcapath' => $source->sslcapath]]);
        $tokenResponse = $tokenDispatcher->sendTokenRequest($tokenRequest);

        $userDispatcher = new InfoDispatcher();
        //$userDispatcher->setOptions(['http_options' => ['sslcapath' => $source->sslcapath]]);

        $infoRequest = new InfoRequest();
        $infoRequest->setClientInfo($clientInfo);
        $infoRequest->setAccessToken($tokenResponse->getAccessToken());

        try {
            $infoResponse = $userDispatcher->sendUserInfoRequest($infoRequest);
            $user = $infoResponse->getClaims();
        } catch (Exception $e) {
            throw new SimpleSAML_Error_Exception('User not authenticated after login attempt.', $e->getCode(), $e);
        }
       
        $attrs = self::getAttributes($user);
 
        $state['Attributes'] = $attrs;

        SimpleSAML_Auth_Source::completeAuth($state);
        assert('FALSE');
    }


    /**
     * This function is called when the user start a logout operation, for example
     * by logging out of a SP that supports single logout.
     *
     * @param array &$state  The logout state array.
     */
    public function logout(&$state) {
        assert('is_array($state)');
        SimpleSAML_Module::callHooks('openidconnect_logout', $state);
    }

}
