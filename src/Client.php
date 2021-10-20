<?php

namespace OK;

use OK\Auth\Credentials\UserRefreshCredentials;

class Client
{

    const API_BASE_PATH = 'https://api.ok.ru/fb.do';

    /**
     * @var array $config
     */
    private $config;


    // private OKApiRequest $request;


    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'base_path' => self::API_BASE_PATH,
            // Path to JSON credentials or an array representing those credentials
            // @see Google\Client::setAuthConfig
            'credentials' => null,

            // https://developers.google.com/console
            'client_id' => '',
            'application_key' => '',
            'application_secret_key' => '',
            // @see Google\Client::setScopes
            'scopes' => null,
            'redirect_uri' => null,
            // Other OAuth2 parameters.
            'hd' => '',
            'prompt' => '',
            'openid.realm' => '',
            'include_granted_scopes' => null,
            'login_hint' => '',
            'request_visible_actions' => '',
            'access_type' => 'online',
            'approval_prompt' => 'auto',

            // function to be called when an access token is fetched
            // follows the signature function ($cacheKey, $accessToken)
            'token_callback' => null,

        ], $config);

        if (!is_null($this->config['credentials'])) {
            $this->setAuthConfig($this->config['credentials']);
            unset($this->config['credentials']);
        }

        if (!is_null($this->config['scopes'])) {
            $this->setScopes($this->config['scopes']);
            unset($this->config['scopes']);
        }

        // Set a default token callback to update the in-memory access token
        if (is_null($this->config['token_callback'])) {
            $this->config['token_callback'] = function ($cacheKey, $newAccessToken) {
                $this->setAccessToken(
                    [
                        'access_token' => $newAccessToken,
                        'expires_in' => 3600, // Google default
                        'created' => time(),
                    ]
                );
            };
        }


        //  protected string $application_key,
        // protected string $app_secret_key,
        // protected string $redirect_uri

        // $this->request = new OKApiRequest($application_key, $app_secret_key);
    }

    // public function getRequest(): OKApiRequest
    // {
    //     return $this->request;
    // }

    // public function __call(string $name, array $arguments)
    // {
    //     return new ("OK\Actions\\" . str_replace('get', '', $name))($this->request);
    // }

    /**
     * Create a URL to obtain user authorization.
     * The authorization endpoint allows the user to first
     * authenticate, and then grant/deny the access request.
     * @param string|array $scope The scope is expressed as an array or list of space-delimited strings.
     * @return string
     */
    public function createAuthUrl($scope = null)
    {
        if (empty($scope)) {
            $scope = $this->prepareScopes();
        }
        if (is_array($scope)) {
            $scope = implode(' ', $scope);
        }

        // only accept one of prompt or approval_prompt
        $approvalPrompt = $this->config['prompt']
            ? null
            : $this->config['approval_prompt'];

        // include_granted_scopes should be string "true", string "false", or null
        $includeGrantedScopes = $this->config['include_granted_scopes'] === null
            ? null
            : var_export($this->config['include_granted_scopes'], true);

        $params = array_filter(
            [
                'access_type' => $this->config['access_type'],
                'approval_prompt' => $approvalPrompt,
                'hd' => $this->config['hd'],
                'include_granted_scopes' => $includeGrantedScopes,
                'login_hint' => $this->config['login_hint'],
                'openid.realm' => $this->config['openid.realm'],
                'prompt' => $this->config['prompt'],
                'response_type' => 'code',
                'scope' => $scope,
                'state' => $this->config['state'],
            ]
        );

        // If the list of scopes contains plus.login, add request_visible_actions
        // to auth URL.
        $rva = $this->config['request_visible_actions'];
        if (strlen($rva) > 0 && false !== strpos($scope, 'plus.login')) {
            $params['request_visible_actions'] = $rva;
        }

        $auth = $this->getOAuth2Service();

        return (string) $auth->buildFullAuthorizationUri($params);
    }

    /**
     * Set the scopes to be requested. Must be called before createAuthUrl().
     * Will remove any previously configured scopes.
     * @param string|array $scope_or_scopes, ie:
     *    array(
     *        'https://www.googleapis.com/auth/plus.login',
     *        'https://www.googleapis.com/auth/moderator'
     *    );
     */
    public function setScopes($scope_or_scopes)
    {
        $this->requestedScopes = array();
        $this->addScope($scope_or_scopes);
    }

    /**
     * This functions adds a scope to be requested as part of the OAuth2.0 flow.
     * Will append any scopes not previously requested to the scope parameter.
     * A single string will be treated as a scope to request. An array of strings
     * will each be appended.
     * @param $scope_or_scopes string|array e.g. "profile"
     */
    public function addScope($scope_or_scopes)
    {
        if (is_string($scope_or_scopes) && !in_array($scope_or_scopes, $this->requestedScopes)) {
            $this->requestedScopes[] = $scope_or_scopes;
        } else if (is_array($scope_or_scopes)) {
            foreach ($scope_or_scopes as $scope) {
                $this->addScope($scope);
            }
        }
    }

    /**
     * Returns the list of scopes requested by the client
     * @return array the list of scopes
     *
     */
    public function getScopes()
    {
        return $this->requestedScopes;
    }

    /**
     * @return string|null
     * @visible For Testing
     */
    public function prepareScopes()
    {
        if (empty($this->requestedScopes)) {
            return null;
        }

        return implode(' ', $this->requestedScopes);
    }

    /**
     * Set the access token used for requests.
     *
     * Note that at the time requests are sent, tokens are cached. A token will be
     * cached for each combination of service and authentication scopes. If a
     * cache pool is not provided, creating a new instance of the client will
     * allow modification of access tokens. If a persistent cache pool is
     * provided, in order to change the access token, you must clear the cached
     * token by calling `$client->getCache()->clear()`. (Use caution in this case,
     * as calling `clear()` will remove all cache items, including any items not
     * related to Google API PHP Client.)
     *
     * @param string|array $token
     * @throws InvalidArgumentException
     */
    public function setAccessToken($token)
    {
        if (is_string($token)) {
            if ($json = json_decode($token, true)) {
                $token = $json;
            } else {
                // assume $token is just the token string
                $token = array(
                    'access_token' => $token,
                );
            }
        }
        if ($token == null) {
            throw new InvalidArgumentException('invalid json token');
        }
        if (!isset($token['access_token'])) {
            throw new InvalidArgumentException("Invalid token format");
        }
        $this->token = $token;
    }

    public function getAccessToken()
    {
        return $this->token;
    }

    /**
     * @return string|null
     */
    public function getRefreshToken()
    {
        if (isset($this->token['refresh_token'])) {
            return $this->token['refresh_token'];
        }

        return null;
    }

    /**
     * Set the OAuth 2.0 Client ID.
     * @param string $clientId
     */
    public function setClientId($clientId)
    {
        $this->config['client_id'] = $clientId;
    }

    public function getClientId()
    {
        return $this->config['client_id'];
    }

    /**
     * Set the OAuth 2.0 Client Secret.
     * @param string $clientSecret
     */
    public function setClientSecret($clientSecret)
    {
        $this->config['client_secret'] = $clientSecret;
    }

    public function getClientSecret()
    {
        return $this->config['client_secret'];
    }

    /**
     * Set the OAuth 2.0 Redirect URI.
     * @param string $redirectUri
     */
    public function setRedirectUri($redirectUri)
    {
        $this->config['redirect_uri'] = $redirectUri;
    }

    public function getRedirectUri()
    {
        return $this->config['redirect_uri'];
    }

    /**
     * Set OAuth 2.0 "state" parameter to achieve per-request customization.
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-3.1.2.2
     * @param string $state
     */
    public function setState($state)
    {
        $this->config['state'] = $state;
    }



    private function createUserRefreshCredentials($scope, $refreshToken)
    {
        $creds = array_filter(
            array(
                'client_id' => $this->getClientId(),
                'client_secret' => $this->getClientSecret(),
                'refresh_token' => $refreshToken,
            )
        );

        return new UserRefreshCredentials($scope, $creds);
    }
}
