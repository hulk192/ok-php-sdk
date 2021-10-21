<?php

namespace OK\Auth;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Psr\Http\Message\UriInterface;

class OAuth2
{

    public static array $knownGrantTypes = [
        'authorization_code',
        'refresh_token',
    ];

    private UriInterface $authorizationUri;
    private UriInterface $tokenCredentialUri;
    private ?UriInterface $redirectUri;
    private string|int $clientId;
    private string $clientKey;
    private string $clientSecret;
    private ?array $scope;
    private string $state;
    private string $code;
    private int $expiry;
    private ?string $grantType;
    private string $refreshToken;
    private string $accessToken;
    private string $idToken;
    private ?int $expiresIn;
    private int $expiresAt;


    /**
     * OKOAuth constructor.
     *
     */
    public function __construct(array $config)
    {
        $opts = array_merge([
            'client_id' => null,
            'application_key' => null,
            'application_secret_key' => null,
            'authorizationUri' => null,
            'tokenCredentialUri' => null,
            'redirectUri' => null,
            'state' => null,
            'scope' => null,
        ], $config);

        $this->setAuthorizationUri($opts['authorizationUri']);
        $this->setRedirectUri($opts['redirectUri']);
        $this->setTokenCredentialUri($opts['tokenCredentialUri']);
        $this->setState($opts['state']);
        $this->setClientId($opts['clientId']);
        $this->setClientSecret($opts['clientSecret']);
        $this->setScope($opts['scope']);
        $this->updateToken($opts);
    }

//    /**
//     * @param string $code Код авторизации
//     * @param int $application_id Идентификатор приложения {application id}
//     * @param string $client_secret Секретный ключ приложения {application_secret_key}
//     * @param string $redirect_uri Тот же URI переадресации
//     * @return \stdClass
//     * @throws \GuzzleHttp\Exception\GuzzleException
//     */
//    public function getAccessToken(
//        string $code,
//        int $application_id,
//        string $client_secret,
//        string $redirect_uri
//    ): \stdClass {
//        $params = [
//            'code' => $code,
//            'client_id' => $application_id,
//            'client_secret' => $client_secret,
//            'redirect_uri' => $redirect_uri,
//            'grant_type' => 'authorization_code',
//        ];
//        return json_decode($this->http_client->post('https://api.ok.ru/oauth/token.do',
//            ['query' => $params])->getBody()->getContents());
//    }

//    /**
//     * @param string $refresh_token Маркер обновления
//     * @param int $application_id Идентификатор приложения {application id}
//     * @param string $client_secret Секретный ключ приложения {application_secret_key}
//     * @return \stdClass
//     * @throws \GuzzleHttp\Exception\GuzzleException
//     */
//    public function getAccessTokenByRefreshToken(
//        string $refresh_token,
//        int $application_id,
//        string $client_secret
//    ): \stdClass {
//        $params = [
//            'refresh_token' => $refresh_token,
//            'client_id' => $application_id,
//            'client_secret' => $client_secret,
//            'grant_type' => 'refresh_token',
//        ];
//        return json_decode($this->http_client->post('https://api.ok.ru/oauth/token.do',
//            ['query' => $params])->getBody()->getContents());
//    }

    public function fetchAuthToken(callable $httpHandler = null)
    {
        if (is_null($httpHandler)) {
            $httpHandler = HttpHandlerFactory::build(HttpClientCache::getHttpClient());
        }

        $response = $httpHandler($this->generateCredentialsRequest());
        $credentials = $this->parseTokenResponse($response);
        $this->updateToken($credentials);

        return $credentials;
    }

    public function updateToken(array $config)
    {
        $opts = array_merge([
            'extensionParams' => [],
            'access_token' => null,
            'id_token' => null,
            'expires_in' => null,
            'expires_at' => null,
            'issued_at' => null,
        ], $config);

        $this->setExpiresAt($opts['expires_at']);
        $this->setExpiresIn($opts['expires_in']);


        $this->setAccessToken($opts['access_token']);
        $this->setIdToken($opts['id_token']);
        // The refresh token should only be updated if a value is explicitly
        // passed in, as some access token responses do not include a refresh
        // token.
        if (array_key_exists('refresh_token', $opts)) {
            $this->setRefreshToken($opts['refresh_token']);
        }
    }

    public function buildFullAuthorizationUri(array $config = []): UriInterface
    {
        if (is_null($this->getAuthorizationUri())) {
            throw new InvalidArgumentException('requires an authorizationUri to have been set');
        }
        $params = array_merge([
            'client_id' => $this->clientId,
            'scope' => $this->getScope(),
            'response_type' => 'code',
            'redirect_uri' => $this->redirectUri,
            'layout' => 'w',
            'state' => $this->state,
        ], $config);

        // Validate the auth_params
        if (is_null($params['client_id'])) {
            throw new InvalidArgumentException('missing the required client identifier');
        }
        if (is_null($params['redirect_uri'])) {
            throw new InvalidArgumentException('missing the required redirect URI');
        }
        // Construct the uri object; return it if it is valid.
        $result = clone $this->authorizationUri;
        $existingParams = Query::parse($result->getQuery());

        $result = $result->withQuery(Query::build(array_merge($existingParams, $params)));

        if ($result->getScheme() != 'https') {
            throw new InvalidArgumentException('Authorization endpoint must be protected by TLS');
        }
        return $result;
    }

    public function setAuthorizationUri(string $uri)
    {
        $this->authorizationUri = $this->coerceUri($uri);
    }

    public function getAuthorizationUri(): UriInterface
    {
        return $this->authorizationUri;
    }

    public function setTokenCredentialUri(string $uri)
    {
        $this->tokenCredentialUri = $this->coerceUri($uri);
    }

    public function getTokenCredentialUri(): UriInterface
    {
        return $this->tokenCredentialUri;
    }

    public function setRedirectUri(string $uri = null)
    {
        if (is_null($uri)) {
            $this->redirectUri = null;
            return;
        }
        if (!$this->isAbsoluteUri($uri)) {
            throw new InvalidArgumentException('Redirect URI must be absolute');
        }
        $this->redirectUri = $this->coerceUri($uri);
    }

    public function getRedirectUri(): UriInterface
    {
        return $this->redirectUri;
    }

    public function setScope(array $scope = null)
    {
        if (is_null($scope)) {
            $this->scope = null;
        } elseif (is_string($scope)) {
            $this->scope = explode(';', $scope);
        } elseif (is_array($scope)) {
            $this->scope = $scope;
        } else {
            throw new InvalidArgumentException('scopes should be a string or array of strings');
        }
    }

    public function getScope(): string
    {
        return implode(';', $this->scope);
    }

    public function setGrantType($grantType)
    {
        if (in_array($grantType, self::$knownGrantTypes)) {
            $this->grantType = $grantType;
        } else {
            // validate URI
            if (!$this->isAbsoluteUri($grantType)) {
                throw new InvalidArgumentException(
                    'invalid grant type'
                );
            }
            $this->grantType = (string)$grantType;
        }
    }

    public function getGrantType(): ?string
    {
        if (!is_null($this->grantType)) {
            return $this->grantType;
        }

        if (!is_null($this->code)) {
            return 'authorization_code';
        }

        if (!is_null($this->refreshToken)) {
            return 'refresh_token';
        }
        return null;
    }

    public function setState($state)
    {
        $this->state = $state;
    }

    public function getState(): string
    {
        return $this->state;
    }

    public function setCode(string $code)
    {
        $this->code = $code;
    }

    public function getCode(): string
    {
        return $this->code;
    }

    public function setClientId($clientId)
    {
        $this->clientId = $clientId;
    }

    public function getClientId(): int|string
    {
        return $this->clientId;
    }

    public function setClientKey($clientKey)
    {
        $this->clientKey = $clientKey;
    }

    public function getClientKey(): string
    {
        return $this->clientKey;
    }

    public function setClientSecret($clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    public function setExpiry(int $expiry)
    {
        $this->expiry = $expiry;
    }

    public function getExpiry(): int
    {
        return $this->expiry;
    }

    public function setExpiresIn(?int $expiresIn = null)
    {
        $this->expiresIn = $expiresIn;
    }

    public function getExpiresIn(): ?int
    {
        return $this->expiresIn;
    }

    public function getExpiresAt(): ?int
    {
        if (!is_null($this->expiresAt)) {
            return $this->expiresAt;
        }
        return null;
    }


    public function isExpired(): bool
    {
        $expiration = $this->getExpiresAt();
        $now = time();

        return !is_null($expiration) && $now >= $expiration;
    }

    public function setExpiresAt($expiresAt)
    {
        $this->expiresAt = $expiresAt;
    }

    public function getAccessToken()
    {
        return $this->accessToken;
    }

    public function setAccessToken(string $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    public function getIdToken(): string
    {
        return $this->idToken;
    }

    public function setIdToken($idToken)
    {
        $this->idToken = $idToken;
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken($refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }

    public function getLastReceivedToken()
    {
        if ($token = $this->getAccessToken()) {
            // the bare necessity of an auth token
            $authToken = [
                'access_token' => $token,
                'expires_in' => $this->getExpiresIn(),
            ];
        } else {
            return null;
        }
        if ($expiresIn = $this->getExpiresIn()) {
            $authToken['expires_in'] = $expiresIn;
        }
        if ($refreshToken = $this->getRefreshToken()) {
            $authToken['refresh_token'] = $refreshToken;
        }
        return $authToken;
    }

    private function coerceUri(string|UriInterface $uri): \Psr\Http\Message\UriInterface
    {
        return Utils::uriFor($uri);
    }

    private function isAbsoluteUri(string|UriInterface $uri): bool
    {
        $uri = $this->coerceUri($uri);

        return $uri->getScheme() && ($uri->getHost() || $uri->getPath());
    }

    private function addClientCredentials(&$params): array
    {
        $clientId = $this->getClientId();
        $clientKey = $this->getClientKey();
        $clientSecret = $this->getClientSecret();

        if ($clientId && $clientKey && $clientSecret) {
            $params['client_id'] = $clientId;
            $params['application_key'] = $clientKey;
            $params['application_secret_key'] = $clientSecret;
        }

        return $params;
    }
}
