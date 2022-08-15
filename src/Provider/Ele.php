<?php

namespace Sindll\OAuth2\Client\Provider;

use UnexpectedValueException;
use Illuminate\Support\Str;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\QueryBuilderTrait;

class Ele extends AbstractProvider
{
    use QueryBuilderTrait;

    /**
     * @var string
     */
    private $urlAuthorize = 'https://open-auth.ele.me/oauth2/authorize';

    /**
     * @var string
     */
    private $urlAccessToken = 'https://open-auth.ele.me/oauth2/token';

    /**
     * @var string
     */
    private $urlRequestPrefix = 'https://api-be.ele.me/';

    /**
     * @inheritdoc
     */
    public function getBaseAuthorizationUrl()
    {
    	return $this->urlAuthorize;
    }

    protected function getAuthorizationParameters(array $options)
    {
        if (empty($options['state'])) {
            $options['state'] = $this->getRandomState();
        }

        // Store the state as it may need to be accessed later on.
        $this->state = $options['state'];

        // Business code layer might set a different redirect_uri parameter
        // depending on the context, leave it as-is
        if (!isset($options['redirect_uri'])) {
            $options['redirect_uri'] = $this->redirectUri;
        }

        $options['client_id'] = $this->clientId;

        return $options;
    }

    /**
     * @inheritdoc
     */
    public function getBaseAccessTokenUrl(array $params)
    {
    	return $this->urlAccessToken;
    }

    /**
     * @inheritdoc
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
    	return $this->urlAccessToken;
    }

    /**
     * @inheritdoc
     */
    public function getDefaultScopes()
    {

    }

    /**
     * @inheritdoc
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($data['body']['errno'] != 0) {
            $code  = $data['body']['errno'];
            $error = $data['body']['error'];
            throw new IdentityProviderException($error, $code, $data);
        }
    }

    /**
     * @inheritdoc
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {

    }


    public function getBaseRquestPrefixUrl()
    {
        return $this->urlRequestPrefix;
    }

    protected function getRequestUrl()
    {
        return $this->getBaseRquestPrefixUrl();
    }

    protected function getRequestParametersWithSecret(array $options)
    {
        $options['source']    = $this->clientId;
        $options['timestamp'] = time();
        $options['version']   = 3;
        $options['ticket']    = strtoupper(Str::uuid());
        $options['encrypt']   = 'aes';

        $options['sign'] = $this->sign($options);

        return $options;
    }

    protected function sign($params)
    {
        $params['secret'] = $this->clientSecret;
        ksort($params);

        $tmp = [];
        foreach ($params as $key => $value) {
            $tmp[] = "$key=$value";
        }

        $string = implode('&', $tmp);

        $sign = strtoupper(md5($string));

        return $sign;
    }

    public function request($cmd, array $params = [])
    {
        $url = $this->getRequestUrl();

        $params  = $this->getRequestParametersWithSecret([
            'cmd'  => $cmd,
            'body' => $params? json_encode($params): '{}',
        ]);

        $options = [
            'headers' => [
                'content-type' => 'application/x-www-form-urlencoded'
            ],
            'body' => $this->buildQueryString($params),
        ];
        $request = $this->getRequest('POST', $url, $options);

        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        return $response;
    }

    public function requestWithToken($token, $cmd, array $params = [])
    {
        $url = $this->getRequestUrl();

        $params  = $this->getRequestParameters([
            'access_token'  => $token->getToken(),
            'cmd'  			=> $cmd,
            'body' 		    => $body? json_encode($body): '{}',
        ]);

        $options = [
            'headers' => [
                'content-type' => 'application/x-www-form-urlencoded'
            ],
            'body' => $this->buildQueryString($params),
        ];
        $request = $this->getRequest($method, $url, $options);

        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        return $response;
    }
}
