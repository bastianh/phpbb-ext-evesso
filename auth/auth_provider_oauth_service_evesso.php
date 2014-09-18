<?php
/**
 * EVE SSO OAuth service
 *
 * @package auth
 */

namespace dafire\evesso\auth;

require_once dirname(__FILE__) . '/oauth_oauth2_evesso.php';

class auth_provider_oauth_service_evesso extends \phpbb\auth\provider\oauth\service\base
{

    /**
     * phpBB config
     *
     * @var \phpbb\config\config
     */
    protected $config;

    /**
     * phpBB request
     *
     * @var \phpbb\request\request_interface
     */
    protected $request;

    /**
     * Constructor
     *
     * @param        \phpbb\config\config $config
     * @param        \phpbb\request\request_interface $request
     */
    public function __construct(\phpbb\config\config $config, \phpbb\request\request_interface $request)
    {
        global $user;
        $user->add_lang_ext('dafire/evesso','common');

        $this->config = $config;
        $this->request = $request;
    }


    /**
     * {@inheritdoc}
     */
    public function get_service_credentials()
    {
        return array(
            'key' => $this->config['auth_oauth_evesso_key'],
            'secret' => $this->config['auth_oauth_evesso_secret'],
        );
    }

    /**
     * {@inheritdoc}
     */
    public function perform_auth_login()
    {
        if (!($this->service_provider instanceof \OAuth\OAuth2\Service\Evesso)) {
            throw new \phpbb\auth\provider\oauth\service\exception('AUTH_PROVIDER_OAUTH_ERROR_INVALID_SERVICE_TYPE');
        }

        $this->service_provider->requestAccessToken($this->request->variable('code', ''));

        $result = json_decode($this->service_provider->request('verify'), true);

        return $result['CharacterID'];
    }

    /**
     * {@inheritdoc}
     */
    public function perform_token_auth()
    {
        if (!($this->service_provider instanceof \OAuth\OAuth2\Service\Evesso)) {
            throw new \phpbb\auth\provider\oauth\service\exception('AUTH_PROVIDER_OAUTH_ERROR_INVALID_SERVICE_TYPE');
        }


        $result = json_decode($this->service_provider->request('verify'), true);

        return $result['CharacterID'];
    }


}