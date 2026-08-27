<?php

declare(strict_types=1);

// Prefer Roundcube's dependency tree when this plugin also has a local vendor
// directory. Loading duplicate PEAR classes from both trees is fatal when mail
// composition lazily initializes Mail_mime.
$roundcubeMailMime = defined('RCUBE_INSTALL_PATH')
    ? RCUBE_INSTALL_PATH . 'vendor/pear/mail_mime/Mail/mime.php'
    : null;
if (!class_exists('Mail_mime', false) && $roundcubeMailMime !== null && is_file($roundcubeMailMime)) {
    require_once $roundcubeMailMime;
}

// Needed for plugin-only installations. Register it after Roundcube's root
// autoloader so plugin dependencies cannot shadow host Roundcube classes.
$oidcAutoloader = @include_once __DIR__ . '/vendor/autoload.php';
if ($oidcAutoloader instanceof \Composer\Autoload\ClassLoader) {
    $oidcAutoloader->unregister();
    $oidcAutoloader->register(false);
}

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Small adapter exposing only the discovery values that the plugin must enforce.
 */
final class roundcube_oidc_client extends OpenIDConnectClient
{
    /** @var list<string> */
    private $allowedEndpointHosts = [];

    /** @var bool */
    private $allowPrivateEndpointIps = false;

    /** @var string|null */
    private $safeResponseContentType;

    /** @param list<string> $hosts */
    public function setEndpointPolicy(array $hosts, bool $allowPrivateIps): void
    {
        $this->allowedEndpointHosts = array_values(array_unique(array_map('strtolower', $hosts)));
        $this->allowPrivateEndpointIps = $allowPrivateIps;
    }

    public function validateDiscovery(string $expectedIssuer, bool $requireUserInfo): void
    {
        $discoveredIssuer = $this->getWellKnownConfigValue('issuer');
        if (!is_string($discoveredIssuer) || !hash_equals($expectedIssuer, $discoveredIssuer)) {
            throw new OpenIDConnectClientException('The discovered issuer does not exactly match oidc_url');
        }

        $required = ['authorization_endpoint', 'token_endpoint', 'jwks_uri'];
        if ($requireUserInfo) {
            $required[] = 'userinfo_endpoint';
        }

        foreach ($required as $name) {
            $endpoint = $this->getProviderConfigValue($name);
            if (!is_string($endpoint)) {
                throw new OpenIDConnectClientException("The provider's {$name} is invalid");
            }
            $this->assertSafeEndpoint($endpoint);
            $this->resolveEndpointHost(strtolower((string) parse_url($endpoint, PHP_URL_HOST)));
        }
    }

    public function requirePkceS256(): void
    {
        $methods = $this->getProviderConfigValue('code_challenge_methods_supported', []);

        if (!is_array($methods) || !in_array('S256', $methods, true)) {
            throw new OpenIDConnectClientException('The provider does not advertise PKCE S256 support');
        }

        $this->setCodeChallengeMethod('S256');
    }

    public function validateCallbackState(string $state): void
    {
        $expected = $this->getState();
        if (!is_string($expected) || !hash_equals($expected, $state)) {
            throw new OpenIDConnectClientException('Authorization response state mismatch');
        }
    }

    public function clearCodeVerifier(): void
    {
        $this->unsetCodeVerifier();
    }

    public function getEndSessionEndpoint(): ?string
    {
        $endpoint = $this->getProviderConfigValue('end_session_endpoint', false);

        if (is_string($endpoint) && $endpoint !== '') {
            $this->assertSafeEndpoint($endpoint);
            $this->resolveEndpointHost(strtolower((string) parse_url($endpoint, PHP_URL_HOST)));
        }

        return is_string($endpoint) && $endpoint !== '' ? $endpoint : null;
    }

    #[\Override]
    public function getResponseContentType()
    {
        return $this->safeResponseContentType;
    }

    /**
     * The upstream client follows redirects for token/JWKS/UserInfo POSTs. That
     * can leak client credentials to a redirected host. This transport accepts
     * HTTPS endpoints on an explicit host allowlist and never follows redirects.
     *
     * @param string|null $post_body
     * @param list<string> $headers
     * @return string
     */
    #[\Override]
    protected function fetchURL(string $url, string $post_body = null, array $headers = [])
    {
        $this->assertSafeEndpoint($url);
        $parts = parse_url($url);
        $host = strtolower((string) $parts['host']);
        $port = (int) ($parts['port'] ?? 443);
        $addresses = $this->resolveEndpointHost($host);
        $response = '';
        $tooLarge = false;
        $curl = curl_init();

        if ($curl === false) {
            throw new OpenIDConnectClientException('Could not initialize the OIDC HTTP client');
        }

        if ($post_body !== null) {
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $post_body);
            $headers[] = is_object(json_decode($post_body, false))
                ? 'Content-Type: application/json'
                : 'Content-Type: application/x-www-form-urlencoded';
        }

        $resolve = $host . ':' . $port . ':' . implode(',', array_map(
            static fn(string $ip): string => str_contains($ip, ':') ? '[' . $ip . ']' : $ip,
            $addresses
        ));

        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_USERAGENT => $this->getUserAgent(),
            CURLOPT_HEADER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_CONNECTTIMEOUT => min(10, $this->timeOut),
            CURLOPT_TIMEOUT => $this->timeOut,
            CURLOPT_RESOLVE => [$resolve],
            CURLOPT_WRITEFUNCTION => static function ($curlHandle, string $chunk) use (&$response, &$tooLarge): int {
                if (strlen($response) + strlen($chunk) > 2 * 1024 * 1024) {
                    $tooLarge = true;
                    return 0;
                }

                $response .= $chunk;
                return strlen($chunk);
            },
        ]);

        $success = curl_exec($curl);
        $this->responseCode = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $contentType = curl_getinfo($curl, CURLINFO_CONTENT_TYPE);
        $this->safeResponseContentType = is_string($contentType)
            ? strtolower(trim(explode(';', $contentType, 2)[0]))
            : null;

        if ($success === false) {
            $message = $tooLarge ? 'OIDC response exceeded 2 MiB' : 'OIDC HTTPS request failed: ' . curl_error($curl);
            curl_close($curl);
            throw new OpenIDConnectClientException($message);
        }

        curl_close($curl);

        if ($this->responseCode >= 300 && $this->responseCode < 400) {
            throw new OpenIDConnectClientException('OIDC endpoint redirects are not allowed');
        }

        return $response;
    }

    private function assertSafeEndpoint(string $url): void
    {
        $parts = parse_url($url);
        $host = is_array($parts) && isset($parts['host']) ? strtolower($parts['host']) : '';

        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || $host === ''
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || !in_array($host, $this->allowedEndpointHosts, true)
        ) {
            throw new OpenIDConnectClientException('OIDC endpoint is not an allowlisted HTTPS URL');
        }
    }

    /** @return list<string> */
    private function resolveEndpointHost(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $addresses = [$host];
        } else {
            $records = dns_get_record($host, DNS_A | DNS_AAAA);
            $addresses = [];
            foreach ($records ?: [] as $record) {
                $address = $record['ip'] ?? $record['ipv6'] ?? null;
                if (is_string($address)) {
                    $addresses[] = $address;
                }
            }
            $addresses = array_values(array_unique($addresses));
        }

        if ($addresses === []) {
            throw new OpenIDConnectClientException('The OIDC endpoint host did not resolve');
        }

        if (!$this->allowPrivateEndpointIps) {
            foreach ($addresses as $address) {
                if (!filter_var(
                    $address,
                    FILTER_VALIDATE_IP,
                    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
                )) {
                    throw new OpenIDConnectClientException('The OIDC endpoint resolved to a private or reserved address');
                }
            }
        }

        return $addresses;
    }
}

/**
 * Authenticate a Roundcube user with OpenID Connect, then ask Roundcube itself
 * for the user's IMAP password. The password is never sent to the OIDC provider.
 */
class roundcube_oidc extends rcube_plugin
{
    public $task = 'login|logout|settings';

    private const ACTION = 'plugin.oidc';
    private const LOGOUT_ACTION = 'plugin.oidc-logout';
    private const PASSKEY_START_ACTION = 'plugin.oidc-passkey-start';
    private const PASSKEY_VERIFY_ACTION = 'plugin.oidc-passkey-verify';
    private const PASSKEY_SETTINGS_ACTION = 'plugin.oidc-passkeys';
    private const PASSKEY_REGISTER_OPTIONS_ACTION = 'plugin.oidc-passkey-register-options';
    private const PASSKEY_REGISTER_ACTION = 'plugin.oidc-passkey-register';
    private const PASSKEY_DELETE_ACTION = 'plugin.oidc-passkey-delete';
    private const PENDING_SESSION_KEY = 'roundcube_oidc_pending';
    private const AUTH_SESSION_KEY = 'roundcube_oidc_authenticated';
    private const LOGOUT_STATE_SESSION_KEY = 'roundcube_oidc_logout_state';
    private const PASSKEY_SESSION_KEY = 'roundcube_oidc_passkey_ceremony';

    /** @var array<string, mixed>|null */
    private $login_phase;

    /** @var array<string, mixed>|null */
    private $retry_phase;

    /** @var string|null */
    private $logout_id_token;

    #[\Override]
    public function init(): void
    {
        $this->load_config('config.inc.php.dist');
        $this->load_config('config.inc.php');

        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('loginform_content', [$this, 'loginformContent']);
        $this->add_hook('authenticate', [$this, 'authenticate']);
        $this->add_hook('login_after', [$this, 'loginAfter']);
        $this->add_hook('login_failed', [$this, 'loginFailed']);
        $this->add_hook('logout_after', [$this, 'logoutAfter']);
        $this->add_hook('settings_actions', [$this, 'settingsActions']);

        $this->register_action(self::PASSKEY_SETTINGS_ACTION, [$this, 'passkeySettings']);
        $this->register_action(self::PASSKEY_REGISTER_OPTIONS_ACTION, [$this, 'passkeyRegisterOptions']);
        $this->register_action(self::PASSKEY_REGISTER_ACTION, [$this, 'passkeyRegister']);
        $this->register_action(self::PASSKEY_DELETE_ACTION, [$this, 'passkeyDelete']);
    }

    /**
     * Starts OIDC, handles its callback, and preserves the pending login across
     * Roundcube's deliberate pre-login session destruction.
     *
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function startup(array $args): array
    {
        $rcmail = rcmail::get_instance();

        if ($args['task'] === 'logout' && !empty($_SESSION[self::AUTH_SESSION_KEY]['id_token'])
            && !empty($_SESSION[self::AUTH_SESSION_KEY]['credential_key'])
        ) {
            $this->logout_id_token = $this->decryptSecret(
                $_SESSION[self::AUTH_SESSION_KEY]['id_token'],
                'id-token:' . $_SESSION[self::AUTH_SESSION_KEY]['credential_key']
            );
        }

        if ($args['task'] !== 'login') {
            return $args;
        }

        if ($args['action'] === self::ACTION) {
            return $this->handleOidcRequest($args);
        }

        if ($args['action'] === self::LOGOUT_ACTION) {
            return $this->handleLogoutCallback($args);
        }

        if ($args['action'] === self::PASSKEY_START_ACTION) {
            return $this->handlePasskeyStart($args);
        }

        if ($args['action'] === self::PASSKEY_VERIFY_ACTION) {
            return $this->handlePasskeyVerification($args);
        }

        if ($args['action'] === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $pending = $_SESSION[self::PENDING_SESSION_KEY] ?? null;

            if (is_array($pending) && $this->pendingLoginIsFresh($pending)) {
                // public_html/index.php calls kill_session() before the authenticate
                // hook. Keep the minimum verified context in this request object.
                $this->login_phase = $pending;
            } elseif ($pending !== null) {
                unset($_SESSION[self::PENDING_SESSION_KEY]);
            }
        }

        return $args;
    }

    /**
     * @param array<string, mixed> $form
     * @return array<string, mixed>
     */
    public function loginformContent(array $form): array
    {
        $rcmail = rcmail::get_instance();

        if ($this->retry_phase !== null) {
            $_SESSION[self::PENDING_SESSION_KEY] = $this->retry_phase;
            $this->retry_phase = null;
        }

        $pending = $_SESSION[self::PENDING_SESSION_KEY] ?? null;

        $ceremony = $_SESSION[self::PASSKEY_SESSION_KEY] ?? null;
        if (is_array($ceremony) && ($ceremony['type'] ?? null) === 'authentication'
            && $this->passkeyCeremonyIsFresh($ceremony)
        ) {
            $this->include_script('passkeys.js');
            $rcmail->output->set_env('oidc_passkey_mode', 'authentication');
            $rcmail->output->set_env('oidc_passkey_options', $ceremony['options']);
            $rcmail->output->set_env('oidc_passkey_action', $rcmail->url([
                '_task' => 'login',
                '_action' => self::PASSKEY_VERIFY_ACTION,
            ]));
            $rcmail->output->set_env('oidc_passkey_token', $rcmail->get_request_token());

            $form['inputs'] = [
                'passkey' => [
                    'title' => html::quote('Passkey'),
                    'content' => html::tag('span', ['id' => 'oidc-passkey-status'],
                        html::quote('Use your passkey to open your mailbox.')),
                ],
            ];
            $form['buttons'] = [
                'passkey' => [
                    'outterclass' => 'passkeylogin',
                    'content' => html::tag('button', [
                        'type' => 'button',
                        'id' => 'oidc-passkey-continue',
                        'class' => 'button mainaction submit',
                    ], html::quote('Continue with Passkey')),
                ],
            ];

            return $form;
        }

        if ($ceremony !== null) {
            unset($_SESSION[self::PASSKEY_SESSION_KEY]);
        }

        if (is_array($pending) && $this->pendingLoginIsFresh($pending)) {
            unset($form['inputs']['user'], $form['inputs']['host']);

            $form['inputs'] = [
                'oidc_user' => [
                    'title' => html::quote('OIDC account'),
                    'content' => html::quote((string) $pending['uid']),
                ],
                'password' => $form['inputs']['password'],
            ];

            if (isset($form['buttons']['submit'])) {
                $button = html::tag('button', [
                    'type' => 'submit',
                    'id' => 'rcmloginsubmit',
                    'class' => 'button mainaction submit',
                ], html::quote('Open mailbox'));
                $form['buttons']['submit']['content'] = $button;
            }

            return $form;
        }

        if ($pending !== null) {
            unset($_SESSION[self::PENDING_SESSION_KEY]);
        }

        $label = (string) $rcmail->config->get('oidc_button_label', 'Login with Single-Sign On');
        $href = $rcmail->url(['_task' => 'login', '_action' => self::ACTION]);
        $button = html::a([
            'href' => $href,
            'id' => 'rcmloginoidc',
            'class' => 'button oidc',
        ], html::quote($label));

        $form['buttons']['oidclogin'] = [
            'outterclass' => 'oidclogin',
            'content' => $button,
        ];

        if ($rcmail->config->get('oidc_passkeys_enabled', true)) {
            $passkeyButton = html::a([
                'href' => $rcmail->url([
                    '_task' => 'login',
                    '_action' => self::PASSKEY_START_ACTION,
                ]),
                'id' => 'rcmloginpasskey',
                'class' => 'button passkey',
            ], html::quote('Login with Passkey'));
            $form['buttons']['passkeylogin'] = [
                'outterclass' => 'passkeylogin',
                'content' => $passkeyButton,
            ];
        }

        return $form;
    }

    /**
     * Supplies the verified username and the locally entered password to
     * Roundcube's native login pipeline. Roundcube retains CSRF, rate-limit,
     * session rotation, logging, and login hook behavior.
     *
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function authenticate(array $args): array
    {
        if ($this->login_phase === null) {
            return $args;
        }

        $storedPassword = !empty($this->login_phase['stored_password_used']);

        // A stored-password login is protected by the OIDC state and nonce just
        // validated on this callback. A prompted login must retain Roundcube's
        // own POST CSRF decision.
        if (empty($args['valid']) && !$storedPassword) {
            return $args;
        }

        $args['user'] = $this->login_phase['uid'];
        if ($storedPassword) {
            $args['pass'] = $this->login_phase['password'];
            $args['valid'] = true;
        } else {
            $this->login_phase['password'] = (string) $args['pass'];
        }
        $args['sso'] = true;

        if (!empty($this->login_phase['host'])) {
            $args['host'] = $this->login_phase['host'];
        }

        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function loginAfter(array $args): array
    {
        if ($this->login_phase === null) {
            return $args;
        }

        $rcmail = rcmail::get_instance();
        $identity = $rcmail->user->get_identity();
        $name = $this->login_phase['name'] ?? null;

        if (is_array($identity) && is_string($name) && $name !== '') {
            $rcmail->user->update_identity($identity['identity_id'], ['name' => $name]);
        }

        $_SESSION[self::AUTH_SESSION_KEY] = [
            'issuer' => $this->login_phase['issuer'] ?? '',
            'sub' => $this->login_phase['sub'] ?? '',
            'id_token' => $this->login_phase['id_token'] ?? '',
            'credential_key' => $this->login_phase['credential_key'],
        ];

        if (empty($this->login_phase['stored_password_used'])) {
            try {
                $this->saveCredential(
                    $this->login_phase,
                    (int) $rcmail->user->ID,
                    (string) $this->login_phase['password']
                );
            } catch (Throwable $e) {
                $this->logFailure('Could not save the encrypted IMAP credential', $e);
                $rcmail->output->show_message(
                    'Mailbox opened, but the password could not be saved. You will be asked again next time.',
                    'warning'
                );
            }
        }

        unset($_SESSION[self::PENDING_SESSION_KEY]);
        unset($this->login_phase['password']);
        $this->login_phase = null;

        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function loginFailed(array $args): array
    {
        if ($this->login_phase !== null) {
            if (!empty($this->login_phase['stored_password_used'])
                && ($this->login_phase['source'] ?? 'oidc') !== 'passkey'
            ) {
                try {
                    $this->deleteCredential((string) $this->login_phase['credential_key']);
                } catch (Throwable $e) {
                    $this->logFailure('Could not remove a rejected stored IMAP credential', $e);
                }
            }

            unset($this->login_phase['password']);
            if (($this->login_phase['source'] ?? 'oidc') === 'passkey') {
                rcmail::get_instance()->output->show_message(
                    'The saved mailbox password was rejected. Login with Single-Sign On once to refresh it.',
                    'warning'
                );
                $this->login_phase = null;
                return $args;
            }
            $this->login_phase['stored_password_used'] = false;
            $this->login_phase['created_at'] = time();
            $this->retry_phase = $this->login_phase;
        }

        $this->login_phase = null;

        return $args;
    }

    /** @param array<string, mixed> $args @return array<string, mixed> */
    private function handlePasskeyStart(array $args): array
    {
        $rcmail = rcmail::get_instance();
        $args['action'] = '';

        try {
            if (!$rcmail->config->get('oidc_passkeys_enabled', true)) {
                throw new RuntimeException('Passkey login is disabled');
            }
            if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
                throw new RuntimeException('Passkey login must use GET');
            }

            $options = PublicKeyCredentialRequestOptions::create(
                random_bytes(32),
                rpId: $this->passkeyRpId(),
                allowCredentials: [],
                userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                timeout: 300000
            );
            $_SESSION[self::PASSKEY_SESSION_KEY] = [
                'type' => 'authentication',
                'created_at' => time(),
                'options' => $this->webauthnSerializer()->serialize($options, 'json'),
            ];
            unset($_SESSION[self::PENDING_SESSION_KEY]);
        } catch (Throwable $e) {
            unset($_SESSION[self::PASSKEY_SESSION_KEY]);
            $this->logFailure('Could not start passkey login', $e);
            $rcmail->output->show_message('Passkey login is unavailable.', 'error');
        }

        return $args;
    }

    /** @param array<string, mixed> $args @return array<string, mixed> */
    private function handlePasskeyVerification(array $args): array
    {
        $rcmail = rcmail::get_instance();
        $args['action'] = '';
        $ceremony = $_SESSION[self::PASSKEY_SESSION_KEY] ?? null;
        unset($_SESSION[self::PASSKEY_SESSION_KEY]);

        try {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !$rcmail->check_request(rcube_utils::INPUT_POST)) {
                throw new RuntimeException('Passkey verification request failed CSRF validation');
            }
            if (!is_array($ceremony) || ($ceremony['type'] ?? null) !== 'authentication'
                || !$this->passkeyCeremonyIsFresh($ceremony)
            ) {
                throw new RuntimeException('Passkey ceremony expired');
            }

            $responseJson = rcube_utils::get_input_value('_response', rcube_utils::INPUT_POST, true);
            if (!is_string($responseJson) || $responseJson === '' || strlen($responseJson) > 65536) {
                throw new RuntimeException('Passkey response is missing or too large');
            }

            $serializer = $this->webauthnSerializer();
            $credential = $serializer->deserialize($responseJson, PublicKeyCredential::class, 'json');
            if (!$credential instanceof PublicKeyCredential
                || !$credential->response instanceof AuthenticatorAssertionResponse
            ) {
                throw new RuntimeException('Passkey response has the wrong type');
            }

            $row = $this->loadPasskeyForLogin($credential->rawId);
            $record = $serializer->deserialize(
                (string) $row['credential_record'],
                CredentialRecord::class,
                'json'
            );
            $options = $serializer->deserialize(
                (string) $ceremony['options'],
                PublicKeyCredentialRequestOptions::class,
                'json'
            );
            if (!$record instanceof CredentialRecord || !$options instanceof PublicKeyCredentialRequestOptions) {
                throw new RuntimeException('Stored passkey data is invalid');
            }

            $updated = $this->assertionValidator()->check(
                $record,
                $credential->response,
                $options,
                $this->passkeyRpId(),
                $this->passkeyUserHandle((string) $row['credential_key'])
            );
            $this->updatePasskeyRecord(
                (string) $row['credential_id_hash'],
                (int) $row['record_version'],
                $serializer->serialize($updated, 'json')
            );

            $password = $this->decryptSecret(
                (string) $row['encrypted_password'],
                'imap-password:' . $row['credential_key']
            );
            if ($password === null || $password === '') {
                throw new RuntimeException('The linked mailbox credential cannot be decrypted');
            }

            $this->login_phase = [
                'source' => 'passkey',
                'uid' => (string) $row['username'],
                'password' => $password,
                'stored_password_used' => true,
                'credential_key' => (string) $row['credential_key'],
            ];
            $args['task'] = 'login';
            $args['action'] = 'login';
        } catch (Throwable $e) {
            $this->logFailure('Passkey authentication failed', $e);
            $rcmail->output->show_message('Passkey authentication failed.', 'error');
        }

        return $args;
    }

    /**
     * Implements optional OIDC RP-Initiated Logout after Roundcube has completed
     * its own CSRF-protected local logout.
     *
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    public function logoutAfter(array $args): array
    {
        $rcmail = rcmail::get_instance();
        $redirect = (string) $rcmail->config->get('oidc_post_logout_redirect_uri', '');

        if ($this->logout_id_token === null || $redirect === '') {
            return $args;
        }

        try {
            $this->assertHttpsUrl($redirect, 'oidc_post_logout_redirect_uri');
            parse_str((string) parse_url($redirect, PHP_URL_QUERY), $redirectQuery);
            if (($redirectQuery['_task'] ?? null) !== 'login'
                || ($redirectQuery['_action'] ?? null) !== self::LOGOUT_ACTION
            ) {
                throw new OpenIDConnectClientException(
                    'oidc_post_logout_redirect_uri must target the plugin.oidc-logout action'
                );
            }
            $client = $this->createClient(false);
            $endpoint = $client->getEndSessionEndpoint();

            if ($endpoint === null) {
                return $args;
            }

            $this->assertHttpsUrl($endpoint, 'end_session_endpoint');
            $state = bin2hex(random_bytes(32));
            $_SESSION[self::LOGOUT_STATE_SESSION_KEY] = $state;
            $separator = str_contains($endpoint, '?') ? '&' : '?';
            $url = $endpoint . $separator . http_build_query([
                'id_token_hint' => $this->logout_id_token,
                'post_logout_redirect_uri' => $redirect,
                'state' => $state,
            ], '', '&', PHP_QUERY_RFC3986);

            $rcmail->output->redirect($url);
        } catch (Throwable $e) {
            $this->logFailure('OIDC logout failed', $e);
        }

        return $args;
    }

    /** @param array<string, mixed> $args @return array<string, mixed> */
    public function settingsActions(array $args): array
    {
        if (rcmail::get_instance()->config->get('oidc_passkeys_enabled', true)) {
            $args['actions'][] = [
                'action' => self::PASSKEY_SETTINGS_ACTION,
                'type' => 'link',
                'label' => 'Passkeys',
                'title' => 'Manage passkeys',
            ];
        }

        return $args;
    }

    public function passkeySettings(): void
    {
        $rcmail = rcmail::get_instance();
        $this->register_handler('plugin.body', [$this, 'passkeySettingsBody']);
        $this->include_script('passkeys.js');
        $rcmail->output->set_pagetitle('Passkeys');
        $rcmail->output->set_env('oidc_passkey_mode', 'settings');
        $rcmail->output->send('plugin');
    }

    public function passkeySettingsBody(): string
    {
        $credentialKey = $this->currentCredentialKey();
        $items = '';

        if ($credentialKey !== null) {
            foreach ($this->loadPasskeyList($credentialKey) as $passkey) {
                $delete = html::tag('button', [
                    'type' => 'button',
                    'class' => 'button oidc-passkey-delete',
                    'data-id' => $passkey['credential_id_hash'],
                ], html::quote('Delete'));
                $items .= html::tag('li', [], html::quote($passkey['label']) . ' ' . $delete);
            }
        }

        if ($items === '') {
            $items = html::tag('li', [], html::quote('No passkeys registered.'));
        }

        $notice = $credentialKey === null
            ? html::p(['class' => 'notice'], html::quote(
                'Login with Single-Sign On first so a passkey can be linked to your mailbox.'
            ))
            : html::tag('button', [
                'type' => 'button',
                'id' => 'oidc-passkey-add',
                'class' => 'button mainaction',
            ], html::quote('Add a Passkey'));

        $body = html::tag('h2', [], html::quote('Passkeys'));
        $body .= html::p([], html::quote(
            'Passkeys use your device unlock or security key and the encrypted mailbox password already saved by SSO.'
        ));
        $body .= html::tag('ul', ['id' => 'oidc-passkey-list'], $items);
        $body .= $notice;
        $body .= html::p(['id' => 'oidc-passkey-status'], '');

        return html::div(['class' => 'boxcontent formcontent'], $body);
    }

    public function passkeyRegisterOptions(): void
    {
        $rcmail = rcmail::get_instance();

        try {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                throw new RuntimeException('Registration options require POST');
            }
            $credentialKey = $this->currentCredentialKey();
            if ($credentialKey === null) {
                throw new RuntimeException('This session is not linked to an OIDC mailbox credential');
            }

            $records = $this->loadPasskeyRecords($credentialKey);
            $exclude = [];
            foreach ($records as $row) {
                $record = $this->webauthnSerializer()->deserialize(
                    (string) $row['credential_record'],
                    CredentialRecord::class,
                    'json'
                );
                if ($record instanceof CredentialRecord) {
                    $exclude[] = $record->getPublicKeyCredentialDescriptor();
                }
            }

            $username = (string) ($rcmail->user->get_username() ?: 'mailbox');
            $options = PublicKeyCredentialCreationOptions::create(
                PublicKeyCredentialRpEntity::create($this->passkeyRpName(), $this->passkeyRpId()),
                PublicKeyCredentialUserEntity::create(
                    $username,
                    $this->passkeyUserHandle($credentialKey),
                    $username
                ),
                random_bytes(32),
                [
                    PublicKeyCredentialParameters::createPk(-7),
                    PublicKeyCredentialParameters::createPk(-257),
                ],
                AuthenticatorSelectionCriteria::create(
                    null,
                    AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                    AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
                ),
                PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                $exclude,
                300000
            );
            $json = $this->webauthnSerializer()->serialize($options, 'json');
            $_SESSION[self::PASSKEY_SESSION_KEY] = [
                'type' => 'registration',
                'created_at' => time(),
                'credential_key' => $credentialKey,
                'options' => $json,
            ];
            $rcmail->output->command('plugin.oidc_passkey_options', [
                'mode' => 'registration',
                'options' => $json,
            ]);
        } catch (Throwable $e) {
            unset($_SESSION[self::PASSKEY_SESSION_KEY]);
            $this->logFailure('Could not create passkey registration options', $e);
            $rcmail->output->show_message('Could not start passkey registration.', 'error');
        }
    }

    public function passkeyRegister(): void
    {
        $rcmail = rcmail::get_instance();
        $ceremony = $_SESSION[self::PASSKEY_SESSION_KEY] ?? null;
        unset($_SESSION[self::PASSKEY_SESSION_KEY]);

        try {
            if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !is_array($ceremony)
                || ($ceremony['type'] ?? null) !== 'registration'
                || !$this->passkeyCeremonyIsFresh($ceremony)
                || !is_string($ceremony['credential_key'] ?? null)
                || !hash_equals((string) $ceremony['credential_key'], (string) $this->currentCredentialKey())
            ) {
                throw new RuntimeException('Passkey registration ceremony is invalid or expired');
            }
            $responseJson = rcube_utils::get_input_value('_response', rcube_utils::INPUT_POST, true);
            $label = trim((string) rcube_utils::get_input_value('_label', rcube_utils::INPUT_POST, true));
            if (!is_string($responseJson) || $responseJson === '' || strlen($responseJson) > 65536) {
                throw new RuntimeException('Passkey response is missing or too large');
            }
            if ($label === '' || strlen($label) > 100 || preg_match('/[\x00-\x1F\x7F]/', $label)) {
                $label = 'Passkey';
            }

            $serializer = $this->webauthnSerializer();
            $credential = $serializer->deserialize($responseJson, PublicKeyCredential::class, 'json');
            $options = $serializer->deserialize(
                (string) $ceremony['options'],
                PublicKeyCredentialCreationOptions::class,
                'json'
            );
            if (!$credential instanceof PublicKeyCredential
                || !$credential->response instanceof AuthenticatorAttestationResponse
                || !$options instanceof PublicKeyCredentialCreationOptions
            ) {
                throw new RuntimeException('Passkey registration response has the wrong type');
            }

            $record = $this->attestationValidator()->check(
                $credential->response,
                $options,
                $this->passkeyRpId()
            );
            $this->insertPasskey(
                (string) $ceremony['credential_key'],
                $record,
                $serializer->serialize($record, 'json'),
                $label
            );
            $rcmail->output->show_message('Passkey registered.', 'confirmation');
            $rcmail->output->command('redirect', $rcmail->url([
                '_task' => 'settings',
                '_action' => self::PASSKEY_SETTINGS_ACTION,
            ]));
        } catch (Throwable $e) {
            $this->logFailure('Passkey registration failed', $e);
            $rcmail->output->show_message('Passkey registration failed.', 'error');
        }
    }

    public function passkeyDelete(): void
    {
        $rcmail = rcmail::get_instance();

        try {
            $credentialKey = $this->currentCredentialKey();
            $id = (string) rcube_utils::get_input_value('_id', rcube_utils::INPUT_POST, true);
            if ($_SERVER['REQUEST_METHOD'] !== 'POST' || $credentialKey === null
                || !preg_match('/\A[a-f0-9]{64}\z/', $id)
            ) {
                throw new RuntimeException('Invalid passkey deletion request');
            }
            $db = $rcmail->get_dbh();
            $result = $db->query(
                'DELETE FROM ' . $db->table_name('oidc_webauthn_credentials', true)
                    . ' WHERE `credential_id_hash` = ? AND `credential_key` = ?',
                $id,
                $credentialKey
            );
            if ($error = $db->is_error($result)) {
                throw new RuntimeException('Could not delete passkey: ' . $error);
            }
            $rcmail->output->show_message('Passkey deleted.', 'confirmation');
            $rcmail->output->command('redirect', $rcmail->url([
                '_task' => 'settings',
                '_action' => self::PASSKEY_SETTINGS_ACTION,
            ]));
        } catch (Throwable $e) {
            $this->logFailure('Passkey deletion failed', $e);
            $rcmail->output->show_message('Passkey could not be deleted.', 'error');
        }
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    private function handleLogoutCallback(array $args): array
    {
        $rcmail = rcmail::get_instance();
        $expected = $_SESSION[self::LOGOUT_STATE_SESSION_KEY] ?? null;
        $received = $_GET['state'] ?? null;
        unset($_SESSION[self::LOGOUT_STATE_SESSION_KEY]);
        $args['action'] = '';

        if ($_SERVER['REQUEST_METHOD'] !== 'GET' || !is_string($expected)
            || !is_string($received) || !hash_equals($expected, $received)
        ) {
            $this->logFailure(
                'OIDC logout callback failed',
                new OpenIDConnectClientException('Logout state mismatch')
            );
            $rcmail->output->show_message('OpenID Connect logout could not be verified.', 'error');
            return $args;
        }

        $rcmail->output->show_message('You have been logged out.', 'confirmation');

        return $args;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, mixed>
     */
    private function handleOidcRequest(array $args): array
    {
        $rcmail = rcmail::get_instance();

        if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
            http_response_code(405);
            $rcmail->output->show_message('OIDC requests must use GET.', 'error');
            $args['action'] = '';
            return $args;
        }

        try {
            $issuer = (string) $rcmail->config->get('oidc_url', '');

            if (isset($_GET['iss']) && (!is_string($_GET['iss']) || $_GET['iss'] !== $issuer)) {
                throw new OpenIDConnectClientException('Authorization response issuer mismatch');
            }

            $client = $this->createClient(true);

            if (isset($_GET['code']) || isset($_GET['error'])) {
                if (!isset($_GET['state']) || !is_string($_GET['state'])
                    || (isset($_GET['code']) && !is_string($_GET['code']))
                    || (isset($_GET['error']) && !is_string($_GET['error']))
                ) {
                    throw new OpenIDConnectClientException('Authorization response parameters are invalid');
                }
                $client->validateCallbackState($_GET['state']);
            }

            // The upstream library reads $_REQUEST. Restrict it to this GET-only
            // callback so cookies cannot inject protocol parameters.
            $_REQUEST = $_GET;
            $client->authenticate();
            $client->clearCodeVerifier();

            $claims = $this->validateIdToken($client);
            $identity = $claims;

            if ($rcmail->config->get('oidc_use_userinfo', true)) {
                $userinfo = (array) $client->requestUserInfo();

                if (!isset($userinfo['sub']) || !is_string($userinfo['sub'])
                    || !hash_equals($claims['sub'], $userinfo['sub'])
                ) {
                    throw new OpenIDConnectClientException('UserInfo subject does not match the ID token');
                }

                $identity = array_merge($claims, $userinfo);
            }

            $pending = $this->buildPendingLogin($identity, $claims, $client->getIdToken());

            $stored = $this->loadCredential($pending);
            if ($stored !== null) {
                $pending['uid'] = $stored['username'];
                $pending['password'] = $stored['password'];
                $pending['stored_password_used'] = true;
                $this->login_phase = $pending;

                // Continue through Roundcube's native login pipeline in this
                // request. OIDC state/nonce validation protects this transition.
                $args['task'] = 'login';
                $args['action'] = 'login';
                return $args;
            }

            $pending['stored_password_used'] = false;
            $_SESSION[self::PENDING_SESSION_KEY] = $pending;

            // The normal Roundcube login form provides the local password field
            // and a CSRF token. No password is obtained from OIDC claims.
            $rcmail->output->redirect(['_task' => 'login']);
        } catch (Throwable $e) {
            unset($_SESSION[self::PENDING_SESSION_KEY]);
            $this->logFailure('OIDC authentication failed', $e);
            $rcmail->output->show_message('OpenID Connect authentication failed.', 'error');
            $args['action'] = '';
        }

        return $args;
    }

    private function createClient(bool $requirePkce): roundcube_oidc_client
    {
        $rcmail = rcmail::get_instance();
        $issuer = (string) $rcmail->config->get('oidc_url', '');
        $clientId = (string) $rcmail->config->get('oidc_client', '');
        $clientSecret = (string) $rcmail->config->get('oidc_secret', '');
        $redirectUri = (string) $rcmail->config->get('oidc_redirect_uri', '');

        $this->assertIssuerUrl($issuer);
        $this->assertHttpsUrl($redirectUri, 'oidc_redirect_uri');

        if ($clientId === '') {
            throw new OpenIDConnectClientException('oidc_client is required');
        }

        $client = new roundcube_oidc_client($issuer, $clientId, $clientSecret);
        $issuerHost = strtolower((string) parse_url($issuer, PHP_URL_HOST));
        $allowedHosts = (array) $rcmail->config->get('oidc_allowed_endpoint_hosts', []);
        $allowedHosts[] = $issuerHost;
        $allowedHosts = array_values(array_filter(array_map(
            static fn($host): string => strtolower(trim((string) $host)),
            $allowedHosts
        )));
        $client->setEndpointPolicy(
            $allowedHosts,
            (bool) $rcmail->config->get('oidc_allow_private_endpoint_ips', false)
        );
        $client->setIssuer($issuer);
        $client->setRedirectURL($redirectUri);
        $client->setAllowImplicitFlow(false);
        $client->setVerifyPeer(true);
        $client->setVerifyHost(true);
        $client->setTimeout(max(1, (int) $rcmail->config->get('oidc_timeout', 10)));

        $scope = $rcmail->config->get('oidc_scope', ['openid']);
        $scope = is_array($scope) ? $scope : preg_split('/\s+/', trim((string) $scope), -1, PREG_SPLIT_NO_EMPTY);
        // The client always adds the mandatory openid scope itself.
        $scope = array_values(array_unique(array_filter(
            $scope ?: [],
            static fn($value): bool => is_string($value) && $value !== '' && $value !== 'openid'
        )));
        $client->addScope($scope);
        $client->validateDiscovery($issuer, (bool) $rcmail->config->get('oidc_use_userinfo', true));

        if ($requirePkce) {
            $client->requirePkceS256();
        }

        return $client;
    }

    /**
     * @return array<string, mixed>
     */
    private function validateIdToken(roundcube_oidc_client $client): array
    {
        $rcmail = rcmail::get_instance();
        $claims = (array) $client->getVerifiedClaims();
        $header = (array) $client->getIdTokenHeader();
        $issuer = (string) $rcmail->config->get('oidc_url');
        $clientId = (string) $rcmail->config->get('oidc_client');
        $leeway = max(0, (int) $rcmail->config->get('oidc_clock_skew', 60));
        $now = time();

        foreach (['iss', 'sub', 'aud', 'exp', 'iat', 'nonce'] as $required) {
            if (!array_key_exists($required, $claims)) {
                throw new OpenIDConnectClientException("ID token is missing the {$required} claim");
            }
        }

        if (!is_string($claims['iss']) || !hash_equals($issuer, $claims['iss'])) {
            throw new OpenIDConnectClientException('ID token issuer mismatch');
        }

        if (!is_string($claims['sub']) || $claims['sub'] === '' || strlen($claims['sub']) > 255) {
            throw new OpenIDConnectClientException('ID token subject is invalid');
        }

        $audiences = is_array($claims['aud']) ? $claims['aud'] : [$claims['aud']];
        if (!in_array($clientId, $audiences, true)) {
            throw new OpenIDConnectClientException('ID token audience mismatch');
        }

        if ((count($audiences) > 1 || isset($claims['azp']))
            && (!isset($claims['azp']) || !is_string($claims['azp']) || !hash_equals($clientId, $claims['azp']))
        ) {
            throw new OpenIDConnectClientException('ID token authorized party mismatch');
        }

        if (!is_int($claims['exp']) || $claims['exp'] < $now - $leeway
            || !is_int($claims['iat']) || $claims['iat'] > $now + $leeway
            || !is_string($claims['nonce']) || $claims['nonce'] === ''
        ) {
            throw new OpenIDConnectClientException('ID token time or nonce claims are invalid');
        }

        $allowedAlgorithms = (array) $rcmail->config->get('oidc_allowed_signing_algorithms', ['RS256']);
        if (!isset($header['alg']) || !is_string($header['alg'])
            || $header['alg'] === 'none' || !in_array($header['alg'], $allowedAlgorithms, true)
        ) {
            throw new OpenIDConnectClientException('ID token signing algorithm is not allowed');
        }

        return $claims;
    }

    /**
     * @param array<string, mixed> $identity
     * @param array<string, mixed> $claims
     * @return array<string, mixed>
     */
    private function buildPendingLogin(array $identity, array $claims, string $idToken): array
    {
        $rcmail = rcmail::get_instance();
        $uidField = (string) $rcmail->config->get('oidc_field_uid', 'email');
        $uid = $identity[$uidField] ?? null;

        if (!is_string($uid) || $uid === '' || strlen($uid) > 255 || preg_match('/[\x00-\x1F\x7F]/', $uid)) {
            throw new OpenIDConnectClientException('The configured login claim is missing or invalid');
        }

        if ($uidField === 'email' && $rcmail->config->get('oidc_require_email_verified', true)
            && ($identity['email_verified'] ?? null) !== true
        ) {
            throw new OpenIDConnectClientException('The email claim is not verified');
        }

        $host = null;
        $hostField = (string) $rcmail->config->get('oidc_field_server', '');
        if ($hostField !== '' && isset($identity[$hostField])) {
            $candidate = $identity[$hostField];
            $allowed = (array) $rcmail->config->get('oidc_allowed_imap_hosts', []);

            if (!is_string($candidate) || !in_array($candidate, $allowed, true)) {
                throw new OpenIDConnectClientException('The asserted IMAP server is not allowlisted');
            }

            $host = $candidate;
        }

        $name = $identity['name'] ?? null;
        if (!is_string($name) || strlen($name) > 255 || preg_match('/[\x00-\x1F\x7F]/', $name)) {
            $name = null;
        }

        $credentialKey = hash('sha256', $claims['iss'] . "\0" . $claims['sub']);

        return [
            'created_at' => time(),
            'uid' => $uid,
            'host' => $host,
            'name' => $name,
            'issuer' => $claims['iss'],
            'sub' => $claims['sub'],
            'credential_key' => $credentialKey,
            'id_token' => $this->encryptSecret($idToken, 'id-token:' . $credentialKey),
        ];
    }

    private function webauthnSerializer(): Symfony\Component\Serializer\SerializerInterface
    {
        return (new WebauthnSerializerFactory(new AttestationStatementSupportManager()))->create();
    }

    private function webauthnCeremonyFactory(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins([$this->passkeyOrigin()], false);
        return $factory;
    }

    private function attestationValidator(): AuthenticatorAttestationResponseValidator
    {
        return AuthenticatorAttestationResponseValidator::create(
            $this->webauthnCeremonyFactory()->creationCeremony()
        );
    }

    private function assertionValidator(): AuthenticatorAssertionResponseValidator
    {
        return AuthenticatorAssertionResponseValidator::create(
            $this->webauthnCeremonyFactory()->requestCeremony()
        );
    }

    private function passkeyOrigin(): string
    {
        $origin = (string) rcmail::get_instance()->config->get(
            'oidc_passkey_origin',
            ''
        );
        $parts = parse_url($origin);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query'])
            || isset($parts['fragment']) || (($parts['path'] ?? '') !== '' && ($parts['path'] ?? '') !== '/')
        ) {
            throw new RuntimeException('oidc_passkey_origin must be an HTTPS origin without a path');
        }

        $normalized = 'https://' . strtolower((string) $parts['host']);
        if (isset($parts['port'])) {
            $normalized .= ':' . (int) $parts['port'];
        }
        return $normalized;
    }

    private function passkeyRpId(): string
    {
        $originHost = strtolower((string) parse_url($this->passkeyOrigin(), PHP_URL_HOST));
        $rpId = strtolower((string) rcmail::get_instance()->config->get('oidc_passkey_rp_id', $originHost));
        if ($rpId === '' || $rpId !== $originHost || filter_var($rpId, FILTER_VALIDATE_IP)
            || !preg_match('/\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/', $rpId)
        ) {
            throw new RuntimeException('oidc_passkey_rp_id must exactly match the passkey origin hostname');
        }
        return $rpId;
    }

    private function passkeyRpName(): string
    {
        $name = trim((string) rcmail::get_instance()->config->get('oidc_passkey_rp_name', 'Alghul Mail'));
        if ($name === '' || strlen($name) > 100 || preg_match('/[\x00-\x1F\x7F]/', $name)) {
            throw new RuntimeException('oidc_passkey_rp_name is invalid');
        }
        return $name;
    }

    private function passkeyUserHandle(string $credentialKey): string
    {
        return hash_hmac('sha256', "passkey-user\0" . $credentialKey, $this->credentialEncryptionKey(), true);
    }

    /** @param array<string, mixed> $ceremony */
    private function passkeyCeremonyIsFresh(array $ceremony): bool
    {
        return isset($ceremony['created_at'], $ceremony['options'])
            && is_int($ceremony['created_at'])
            && is_string($ceremony['options'])
            && strlen($ceremony['options']) <= 65536
            && $ceremony['created_at'] >= time() - 300
            && $ceremony['created_at'] <= time() + 60;
    }

    private function currentCredentialKey(): ?string
    {
        $sessionKey = $_SESSION[self::AUTH_SESSION_KEY]['credential_key'] ?? null;
        if (is_string($sessionKey) && preg_match('/\A[a-f0-9]{64}\z/', $sessionKey)) {
            return $sessionKey;
        }

        $rcmail = rcmail::get_instance();
        if (!$rcmail->user || !$rcmail->user->ID) {
            return null;
        }
        $db = $rcmail->get_dbh();
        $result = $db->query(
            'SELECT `credential_key` FROM ' . $db->table_name('oidc_credentials', true)
                . ' WHERE `user_id` = ? ORDER BY `updated` DESC',
            (int) $rcmail->user->ID
        );
        if ($db->is_error($result)) {
            return null;
        }
        $row = $db->fetch_assoc($result);
        return is_array($row) && is_string($row['credential_key'] ?? null)
            ? $row['credential_key']
            : null;
    }

    /** @return list<array<string, mixed>> */
    private function loadPasskeyRecords(string $credentialKey): array
    {
        $db = rcmail::get_instance()->get_dbh();
        $result = $db->query(
            'SELECT `credential_id_hash`, `credential_record`, `record_version`, `label` FROM '
                . $db->table_name('oidc_webauthn_credentials', true)
                . ' WHERE `credential_key` = ? ORDER BY `created` ASC',
            $credentialKey
        );
        if ($error = $db->is_error($result)) {
            throw new RuntimeException('Passkey table is unavailable: ' . $error);
        }
        $rows = [];
        while ($row = $db->fetch_assoc($result)) {
            $rows[] = $row;
        }
        return $rows;
    }

    /** @return list<array{credential_id_hash: string, label: string}> */
    private function loadPasskeyList(string $credentialKey): array
    {
        return array_map(
            static fn(array $row): array => [
                'credential_id_hash' => (string) $row['credential_id_hash'],
                'label' => (string) $row['label'],
            ],
            $this->loadPasskeyRecords($credentialKey)
        );
    }

    /** @return array<string, mixed> */
    private function loadPasskeyForLogin(string $rawId): array
    {
        $db = rcmail::get_instance()->get_dbh();
        $passkeys = $db->table_name('oidc_webauthn_credentials', true);
        $credentials = $db->table_name('oidc_credentials', true);
        $users = $db->table_name('users', true);
        $hash = hash('sha256', $rawId);
        $result = $db->query(
            "SELECT p.`credential_id_hash`, p.`credential_record`, p.`record_version`,"
                . " p.`credential_key`, c.`encrypted_password`, u.`username`"
                . " FROM {$passkeys} p JOIN {$credentials} c ON (c.`credential_key` = p.`credential_key`)"
                . " JOIN {$users} u ON (u.`user_id` = c.`user_id`)"
                . ' WHERE p.`credential_id_hash` = ?',
            $hash
        );
        if ($error = $db->is_error($result)) {
            throw new RuntimeException('Passkey lookup failed: ' . $error);
        }
        $row = $db->fetch_assoc($result);
        if (!is_array($row) || !hash_equals($hash, (string) ($row['credential_id_hash'] ?? ''))) {
            throw new RuntimeException('Unknown passkey');
        }
        return $row;
    }

    private function insertPasskey(
        string $credentialKey,
        CredentialRecord $record,
        string $recordJson,
        string $label
    ): void {
        $db = rcmail::get_instance()->get_dbh();
        $result = $db->query(
            'INSERT INTO ' . $db->table_name('oidc_webauthn_credentials', true)
                . ' (`credential_id_hash`, `credential_key`, `credential_record`, `record_version`, `label`, `created`, `updated`)'
                . ' VALUES (?, ?, ?, 1, ?, ' . $db->now() . ', ' . $db->now() . ')',
            hash('sha256', $record->publicKeyCredentialId),
            $credentialKey,
            $recordJson,
            $label
        );
        if ($error = $db->is_error($result)) {
            throw new RuntimeException('Could not store passkey: ' . $error);
        }
    }

    private function updatePasskeyRecord(string $idHash, int $version, string $recordJson): void
    {
        $db = rcmail::get_instance()->get_dbh();
        $result = $db->query(
            'UPDATE ' . $db->table_name('oidc_webauthn_credentials', true)
                . ' SET `credential_record` = ?, `record_version` = `record_version` + 1,'
                . ' `last_used` = ' . $db->now() . ', `updated` = ' . $db->now()
                . ' WHERE `credential_id_hash` = ? AND `record_version` = ?',
            $recordJson,
            $idHash,
            $version
        );
        if ($error = $db->is_error($result)) {
            throw new RuntimeException('Could not update passkey counter: ' . $error);
        }
        if ($db->affected_rows($result) !== 1) {
            throw new RuntimeException('Concurrent or replayed passkey assertion rejected');
        }
    }

    /**
     * @param array<string, mixed> $pending
     * @return array{username: string, password: string}|null
     */
    private function loadCredential(array $pending): ?array
    {
        $db = rcmail::get_instance()->get_dbh();
        $table = $db->table_name('oidc_credentials', true);
        $users = $db->table_name('users', true);
        $result = $db->query(
            "SELECT c.`oidc_uid`, c.`encrypted_password`, u.`username`"
            . " FROM {$table} c JOIN {$users} u ON (u.`user_id` = c.`user_id`)"
            . ' WHERE c.`credential_key` = ?',
            $pending['credential_key']
        );

        if ($error = $db->is_error($result)) {
            throw new RuntimeException('OIDC credential table is unavailable: ' . $error);
        }

        $row = $db->fetch_assoc($result);
        if (!$row) {
            return null;
        }

        if (!is_string($row['oidc_uid']) || !hash_equals($row['oidc_uid'], (string) $pending['uid'])) {
            throw new OpenIDConnectClientException('The login claim changed for this OIDC subject');
        }

        $password = $this->decryptSecret(
            (string) $row['encrypted_password'],
            'imap-password:' . $pending['credential_key']
        );

        if ($password === null) {
            $this->deleteCredential((string) $pending['credential_key']);
            return null;
        }

        return [
            'username' => (string) $row['username'],
            'password' => $password,
        ];
    }

    /** @param array<string, mixed> $phase */
    private function saveCredential(array $phase, int $userId, string $password): void
    {
        if ($password === '') {
            throw new RuntimeException('Refusing to store an empty IMAP password');
        }

        $db = rcmail::get_instance()->get_dbh();
        $table = $db->table_name('oidc_credentials', true);
        $encrypted = $this->encryptSecret($password, 'imap-password:' . $phase['credential_key']);
        $result = $db->query(
            "UPDATE {$table} SET `user_id` = ?, `oidc_uid` = ?, `encrypted_password` = ?,"
            . ' `updated` = ' . $db->now() . ' WHERE `credential_key` = ?',
            $userId,
            $phase['uid'],
            $encrypted,
            $phase['credential_key']
        );

        if ($error = $db->is_error($result)) {
            throw new RuntimeException('Could not update the OIDC credential: ' . $error);
        }

        if ($db->affected_rows($result) === 0) {
            $result = $db->query(
                "INSERT INTO {$table} (`credential_key`, `user_id`, `oidc_uid`, `encrypted_password`, `created`, `updated`)"
                . ' VALUES (?, ?, ?, ?, ' . $db->now() . ', ' . $db->now() . ')',
                $phase['credential_key'],
                $userId,
                $phase['uid'],
                $encrypted
            );

            if ($error = $db->is_error($result)) {
                throw new RuntimeException('Could not insert the OIDC credential: ' . $error);
            }
        }
    }

    private function deleteCredential(string $credentialKey): void
    {
        $db = rcmail::get_instance()->get_dbh();
        $result = $db->query(
            'DELETE FROM ' . $db->table_name('oidc_credentials', true) . ' WHERE `credential_key` = ?',
            $credentialKey
        );

        if ($error = $db->is_error($result)) {
            throw new RuntimeException('Could not delete the OIDC credential: ' . $error);
        }
    }

    private function encryptSecret(string $cleartext, string $context): string
    {
        $key = $this->credentialEncryptionKey();
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $cleartext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context,
            16
        );

        if ($ciphertext === false || strlen($tag) !== 16) {
            throw new RuntimeException('AES-256-GCM encryption failed');
        }

        return base64_encode("\x01" . $iv . $tag . $ciphertext);
    }

    private function decryptSecret(string $encoded, string $context): ?string
    {
        $payload = base64_decode($encoded, true);
        if ($payload === false || strlen($payload) < 30 || $payload[0] !== "\x01") {
            return null;
        }

        $iv = substr($payload, 1, 12);
        $tag = substr($payload, 13, 16);
        $ciphertext = substr($payload, 29);
        $cleartext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $this->credentialEncryptionKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context
        );

        return is_string($cleartext) ? $cleartext : null;
    }

    private function credentialEncryptionKey(): string
    {
        $encoded = (string) rcmail::get_instance()->config->get('oidc_password_encryption_key', '');
        $key = base64_decode($encoded, true);

        if ($key === false || strlen($key) !== 32) {
            throw new RuntimeException('oidc_password_encryption_key must be a base64-encoded 32-byte key');
        }

        return $key;
    }

    /** @param array<string, mixed> $pending */
    private function pendingLoginIsFresh(array $pending): bool
    {
        $ttl = max(60, (int) rcmail::get_instance()->config->get('oidc_password_prompt_ttl', 300));

        return isset($pending['created_at'], $pending['uid'], $pending['issuer'], $pending['sub'],
                $pending['credential_key'], $pending['id_token'])
            && is_int($pending['created_at'])
            && $pending['created_at'] >= time() - $ttl
            && $pending['created_at'] <= time() + 60;
    }

    private function assertIssuerUrl(string $url): void
    {
        $this->assertHttpsUrl($url, 'oidc_url');

        if (parse_url($url, PHP_URL_QUERY) !== null || parse_url($url, PHP_URL_FRAGMENT) !== null) {
            throw new OpenIDConnectClientException('oidc_url must not contain a query or fragment');
        }
    }

    private function assertHttpsUrl(string $url, string $option): void
    {
        $parts = parse_url($url);

        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
        ) {
            throw new OpenIDConnectClientException("{$option} must be an absolute HTTPS URL");
        }
    }

    private function logFailure(string $context, Throwable $error): void
    {
        $message = preg_replace('/[\r\n]+/', ' ', $error->getMessage());
        rcube::raise_error([
            'code' => 500,
            'type' => 'php',
            'message' => $context . ': ' . $message,
        ], true, false);
    }
}
