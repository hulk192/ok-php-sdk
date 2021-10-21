<?php

namespace OK;

use InvalidArgumentException;
use LogicException;
use OK\Auth\OAuth2;
use Psr\Log\LoggerInterface;

class Client
{
    const OAUTH2_AUTH_URL = 'https://connect.ok.ru/oauth/authorize';
    const OAUTH2_TOKEN_URI = 'https://api.ok.ru/oauth/token.do';
    const API_BASE_PATH = 'https://api.ok.ru/fb.do';

    private array $token;
    private array $config;
    private LoggerInterface $logger;
    protected array $requestedScopes = [];
    private OAuth2 $auth;

    public function __construct(array $config = [])
    {
        $this->config = array_merge(
            [
                'base_path' => self::API_BASE_PATH,
                // https://ok.ru/app/setup
                'client_id' => '',
                'application_key' => '',
                'application_secret_key' => '',
                // Path to JSON credentials or an array representing those credentials
                // @see Google\Client::setAuthConfig
                'credentials' => null,

                // @see OK\Client::setScopes
                'scopes' => null,

                'redirect_uri' => null,
                'state' => null,

                // Other OAuth2 parameters.
                'response_type' => 'code',
                'layout' => 'w',
            ],
            $config
        );

        if (!is_null($this->config['credentials'])) {
            $this->setAuthConfig($this->config['credentials']);
            unset($this->config['credentials']);
        }

        if (!is_null($this->config['scopes'])) {
            $this->setScopes($this->config['scopes']);
            unset($this->config['scopes']);
        }
    }

    public function fetchAccessTokenWithAuthCode($code)
    {
        if (strlen($code) == 0) {
            throw new InvalidArgumentException("Invalid code");
        }

        $auth = $this->getOAuth2Service();
        $auth->setCode($code);
        $auth->setRedirectUri($this->getRedirectUri());

        $httpHandler = HttpHandlerFactory::build($this->getHttpClient());
        $creds = $auth->fetchAuthToken($httpHandler);
        if ($creds && isset($creds['access_token'])) {
            $creds['created'] = time();
            $this->setAccessToken($creds);
        }

        return $creds;
    }

    /**
     * Fetches a fresh OAuth 2.0 access token with the given refresh token.
     * @param string $refreshToken
     * @return array access token
     */
    public function fetchAccessTokenWithRefreshToken($refreshToken = null)
    {
        if (null === $refreshToken) {
            if (!isset($this->token['refresh_token'])) {
                throw new LogicException(
                    'refresh token must be passed in or set as part of setAccessToken'
                );
            }
            $refreshToken = $this->token['refresh_token'];
        }
        $this->getLogger()->info('OAuth2 access token refresh');
        $auth = $this->getOAuth2Service();
        $auth->setRefreshToken($refreshToken);

        $httpHandler = HttpHandlerFactory::build($this->getHttpClient());
        $creds = $auth->fetchAuthToken($httpHandler);
        if ($creds && isset($creds['access_token'])) {
            $creds['created'] = time();
            if (!isset($creds['refresh_token'])) {
                $creds['refresh_token'] = $refreshToken;
            }
            $this->setAccessToken($creds);
        }

        return $creds;
    }

    public function createAuthUrl(?array $scope = null): string
    {
        if (empty($scope)) {
            $scope = $this->prepareScopes();
        }
        if (is_array($scope)) {
            $scope = implode(';', $scope);
        }
        $params = array_filter([
            'response_type' => 'code',
            'scope' => $scope,
            'state' => $this->config['state'],
            'layout' => $this->config['layout'],
        ]);
        $auth = $this->getOAuth2Service();

        return (string)$auth->buildFullAuthorizationUri($params);
    }

    public function setAccessToken(array|string $token)
    {
        if (is_string($token)) {
            if ($json = json_decode($token, true)) {
                $token = $json;
            } else {
                $token = ['access_token' => $token];
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

    public function getAccessToken(): array
    {
        return $this->token;
    }

    public function getRefreshToken()
    {
        return $this->token['refresh_token'] ?? null;
    }

    public function isAccessTokenExpired()
    {
        if (!$this->token) {
            return true;
        }

        $created = 0;
        if (isset($this->token['created'])) {
            $created = $this->token['created'];
        } elseif (isset($this->token['id_token'])) {
            // check the ID token for "iat"
            // signature verification is not required here, as we are just
            // using this for convenience to save a round trip request
            // to the Google API server
            $idToken = $this->token['id_token'];
            if (substr_count($idToken, '.') == 2) {
                $parts = explode('.', $idToken);
                $payload = json_decode(base64_decode($parts[1]), true);
                if ($payload && isset($payload['iat'])) {
                    $created = $payload['iat'];
                }
            }
        }

        // If the token is set to expire in the next 30 seconds.
        return ($created + ($this->token['expires_in'] - 30)) < time();
    }

    /**
     * Set the OAuth 2.0 Client ID.
     * @param string $clientId
     */
    public function setClientId(string $clientId)
    {
        $this->config['client_id'] = $clientId;
    }

    public function getClientId()
    {
        return $this->config['client_id'];
    }

    /**
     * Set the OAuth 2.0 Client Application Key.
     * @param string $clientKey
     */
    public function setClientKey(string $clientKey)
    {
        $this->config['application_key'] = $clientKey;
    }

    public function getClientKey()
    {
        return $this->config['application_key'];
    }

    /**
     * Set the OAuth 2.0 Client Application Secret.
     * @param string $clientSecret
     */
    public function setClientSecret(string $clientSecret)
    {
        $this->config['application_secret_key'] = $clientSecret;
    }

    public function getClientSecret()
    {
        return $this->config['application_secret_key'];
    }

    /**
     * Set the OAuth 2.0 Redirect URI.
     * @param string $redirectUri
     */
    public function setRedirectUri(string $redirectUri)
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

    /**
     * @param string $accessType Possible values for access_type include:
     *  {@code "offline"} to request offline access from the user.
     *  {@code "online"} to request online access from the user.
     */
    public function setLayout($layout)
    {
        $this->config['layout'] = $layout;
    }

    /**
     * Set the scopes to be requested. Must be called before createAuthUrl().
     * Will remove any previously configured scopes.
     * @param array|string $scope_or_scopes , ie:
     *    array(
     *        'VALUABLE_ACCESS',
     *        'LONG_ACCESS_TOKEN',
     *        'PHOTO_CONTENT',
     *        'GROUP_CONTENT',
     *        'VIDEO_CONTENT',
     *        'APP_INVITE',
     *        'GET_EMAIL',
     *    );
     */
    public function setScopes(array|string $scope_or_scopes)
    {
        $this->requestedScopes = [];
        $this->addScope($scope_or_scopes);
    }

    /**
     * This functions adds a scope to be requested as part of the OAuth2.0 flow.
     * Will append any scopes not previously requested to the scope parameter.
     * A single string will be treated as a scope to request. An array of strings
     * will each be appended.
     * @param $scope_or_scopes array|string e.g. "VALUABLE_ACCESS"
     */
    public function addScope(array|string $scope_or_scopes)
    {
        if (is_string($scope_or_scopes) && !in_array($scope_or_scopes, $this->requestedScopes)) {
            $this->requestedScopes[] = $scope_or_scopes;
        } else {
            if (is_array($scope_or_scopes)) {
                foreach ($scope_or_scopes as $scope) {
                    $this->addScope($scope);
                }
            }
        }
    }

    /**
     * Returns the list of scopes requested by the client
     * @return array the list of scopes
     *
     */
    public function getScopes(): array
    {
        return $this->requestedScopes;
    }

    /**
     * @return string|null
     * @visible For Testing
     */
    public function prepareScopes(): ?string
    {
        if (empty($this->requestedScopes)) {
            return null;
        }

        return implode(';', $this->requestedScopes);
    }

    public function setConfig($name, $value)
    {
        $this->config[$name] = $value;
    }

    public function getConfig($name, $default = null)
    {
        return $this->config[$name] ?? $default;
    }

    /**
     * Set the auth config from new or deprecated JSON config.
     * This structure should match the file downloaded from
     * the "Download JSON" button on in the Google Developer
     * Console.
     * @param array|string $config the configuration json
     */
    public function setAuthConfig(array|string $config)
    {
        if (is_string($config)) {
            if (!file_exists($config)) {
                throw new InvalidArgumentException(sprintf('file "%s" does not exist', $config));
            }

            $json = file_get_contents($config);

            if (!$config = json_decode($json, true)) {
                throw new LogicException('invalid json for auth config');
            }
        }
        $this->setClientId($config['client_id']);
        $this->setClientKey($config['application_key']);
        $this->setClientSecret($config['application_secret_key']);
        if (isset($config['redirect_uri'])) {
            $this->setRedirectUri($config['redirect_uri']);
        }
    }

    public function getOAuth2Service(): OAuth2
    {
        return $this->auth = $this->auth ?? $this->createOAuth2Service();
    }

    protected function createOAuth2Service(): OAuth2
    {
        return new OAuth2([
            'client_id' => $this->getClientId(),
            'application_key' => $this->getClientKey(),
            'application_secret_key' => $this->getClientSecret(),
            'authorizationUri' => self::OAUTH2_AUTH_URL,
            'tokenCredentialUri' => self::OAUTH2_TOKEN_URI,
            'redirectUri' => $this->getRedirectUri()
        ]);
    }

    /**
     * Set the Logger object
     * @param LoggerInterface $logger
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @return LoggerInterface
     */
    public function getLogger()
    {
        if (!isset($this->logger)) {
            $this->logger = $this->createDefaultLogger();
        }

        return $this->logger;
    }

    protected function createDefaultLogger()
    {
        $logger = new Logger('google-api-php-client');
        if ($this->isAppEngine()) {
            $handler = new MonologSyslogHandler('app', LOG_USER, Logger::NOTICE);
        } else {
            $handler = new MonologStreamHandler('php://stderr', Logger::NOTICE);
        }
        $logger->pushHandler($handler);

        return $logger;
    }

    /**
     * Set the Http Client object
     * @param ClientInterface $http
     */
    public function setHttpClient(ClientInterface $http)
    {
        $this->http = $http;
    }

    /**
     * @return ClientInterface
     */
    public function getHttpClient()
    {
        if (null === $this->http) {
            $this->http = $this->createDefaultHttpClient();
        }

        return $this->http;
    }

    protected function createDefaultHttpClient()
    {
        $guzzleVersion = null;
        if (defined('\GuzzleHttp\ClientInterface::MAJOR_VERSION')) {
            $guzzleVersion = ClientInterface::MAJOR_VERSION;
        } elseif (defined('\GuzzleHttp\ClientInterface::VERSION')) {
            $guzzleVersion = (int)substr(ClientInterface::VERSION, 0, 1);
        }

        if (5 === $guzzleVersion) {
            $options = [
                'base_url' => $this->config['base_path'],
                'defaults' => ['exceptions' => false],
            ];
            if ($this->isAppEngine()) {
                // set StreamHandler on AppEngine by default
                $options['handler'] = new StreamHandler();
                $options['defaults']['verify'] = '/etc/ca-certificates.crt';
            }
        } elseif (6 === $guzzleVersion || 7 === $guzzleVersion) {
            // guzzle 6 or 7
            $options = [
                'base_uri' => $this->config['base_path'],
                'http_errors' => false,
            ];
        } else {
            throw new LogicException('Could not find supported version of Guzzle.');
        }

        return new GuzzleClient($options);
    }


}
