<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;



class evesso extends AbstractService
{
    public function __construct(Credentials $credentials, ClientInterface $httpClient, TokenStorageInterface $storage, $scopes = array(), UriInterface $baseApiUri = null)
    {
        $scopes = array();
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);
        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://sisilogin.testeveonline.com/oauth/');
        }
    }

    /**
     * @return \OAuth\Common\Http\Uri\UriInterface
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://sisilogin.testeveonline.com/oauth/authorize/');
    }

    /**
     * @return \OAuth\Common\Http\Uri\UriInterface
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://sisilogin.testeveonline.com/oauth/token');
    }

    /**
     * @param string $responseBody
     * @return \OAuth\Common\Token\TokenInterface|\OAuth\OAuth2\Token\StdOAuth2Token
     * @throws \OAuth\Common\Http\Exception\TokenResponseException
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();


        $token->setAccessToken($data['access_token']);
        $token->setRefreshToken($data['refresh_token']);
        $token->setLifetime($data['expires_in']);
        unset($data['access_token']);
        unset($data['refresh_token']);
        unset($data['expires_in']);
        $token->setExtraParams($data);

        return $token;
    }

    /**
     * @return int
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

}
