<?php
/**
 * Created for plugin-core
 * Datetime: 28.02.2020 16:18
 * @author Timur Kasumov aka XAKEPEHOK
 */

namespace Leadvertex\Plugin\Components\Token;


use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Leadvertex\Plugin\Components\Registration\Registration;
use Leadvertex\Plugin\Components\Settings\Settings;
use RuntimeException;

class GraphqlInputToken implements InputTokenInterface
{

    /** @var Token */
    private $inputToken;

    /** @var Token */
    private $pluginToken;

    /** @var Registration */
    private $registration;

    /** @var Settings */
    private $settings;

    /** @var GraphqlInputToken */
    private static $instance = null;

    public function __construct(string $token)
    {
        if (!is_null(self::$instance)) {
            throw new RuntimeException('Some token already loaded');
        }

        $this->inputToken = (new Parser())->parse($token);
        $validation = new ValidationData();
        $validation->setAudience($_ENV['LV_PLUGIN_SELF_URI']);
        if (!$this->inputToken->validate($validation)) {
            throw new TokenException('Invalid backend token', 101);
        }

        self::$instance = $this;
    }

    public function getInputToken(): Token
    {
        return $this->inputToken;
    }

    public function getId(): string
    {
        return $this->getInputToken()->getClaim('jti');
    }

    public function getCompanyId(): string
    {
        return $this->getInputToken()->getClaim('cid');
    }

    public function getBackendUri(): string
    {
        return $this->getInputToken()->getClaim('iss');
    }

    public function getOutputToken(): Token
    {
        return $this->getRegistration()->getSignedToken((string) $this->getInputToken());
    }

    public function getPluginToken(): Token
    {
        if (!isset($this->pluginToken)) {
            $this->pluginToken = (new Parser())->parse(
                $this->inputToken->getClaim('plugin-jwt')
            );

            $validation = new ValidationData();
            $validation->setAudience($_ENV['LV_PLUGIN_SELF_URI']);
            if (!$this->pluginToken->hasClaim('aud') || !$this->pluginToken->validate($validation)) {
                throw new TokenException('Invalid plugin token', 300);
            }

            if (!$this->pluginToken->verify(new Sha512(), $this->getRegistration()->getLVPT())) {
                throw new TokenException('Invalid plugin token sign', 301);
            }

            if ($this->pluginToken->getClaim('jti') !== $this->getInputToken()->getClaim('jti')) {
                throw new TokenException("Mismatch 'jti' of plugin and parent tokens", 302);
            }
        }

        return $this->pluginToken;
    }

    public function getRegistration(): Registration
    {
        if (!isset($this->registration)) {

            $this->registration = Registration::findById(
                $this->getInputToken()->getClaim('plugin')->id,
                $this->getInputToken()->getClaim('plugin')->alias
            );

            if (is_null($this->registration)) {
                throw new TokenException('Plugin was not registered', 200);
            }
        }
        return $this->registration;
    }

    public function getSettings(): Settings
    {
        if (is_null($this->settings)) {
            $registration = $this->getRegistration();
            $this->settings = Settings::findById($registration->getId(), $registration->getFeature());
            if (is_null($this->settings)) {
                $this->settings = new Settings($registration->getId(), $registration->getFeature());
            }
        }
        return $this->settings;
    }

    public static function getInstance(): ?InputTokenInterface
    {
        return self::$instance;
    }
}