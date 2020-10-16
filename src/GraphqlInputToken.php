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

        $this->inputToken = $this->parseInputToken($token);
        $this->registration = $this->findRegistration($this->inputToken);
        $this->pluginToken = $this->parsePluginToken($this->inputToken, $this->registration);

        self::$instance = $this;
    }

    public function getInputToken(): Token
    {
        return $this->inputToken;
    }

    public function getId(): string
    {
        return $this->inputToken->getClaim('jti');
    }

    public function getCompanyId(): string
    {
        return $this->inputToken->getClaim('cid');
    }

    public function getBackendUri(): string
    {
        return $this->inputToken->getClaim('iss');
    }

    public function getOutputToken(): Token
    {
        return $this->registration->getSignedToken((string) $this->inputToken);
    }

    public function getPluginToken(): Token
    {
        return $this->pluginToken;
    }

    public function getRegistration(): Registration
    {
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

    private function parseInputToken(string $token): Token
    {
        $token = (new Parser())->parse($token);

        $validation = new ValidationData();
        $validation->setAudience($_ENV['LV_PLUGIN_SELF_URI']);
        if (!$token->validate($validation)) {
            throw new TokenException('Invalid backend token', 101);
        }

        return $token;
    }

    private function findRegistration(Token $token): Registration
    {
        $registration = Registration::findById(
            $token->getClaim('plugin')->id,
            $token->getClaim('plugin')->alias
        );

        if (is_null($registration)) {
            throw new TokenException('Plugin was not registered', 200);
        }

        return $registration;
    }

    private function parsePluginToken(Token $inputToken, Registration $registration): Token
    {
        $token = (new Parser())->parse(
            $inputToken->getClaim('plugin-jwt')
        );

        $validation = new ValidationData();
        $validation->setAudience($_ENV['LV_PLUGIN_SELF_URI']);
        if (!$token->validate($validation)) {
            throw new TokenException('Invalid plugin token', 300);
        }

        if (!$token->verify(new Sha512(), $registration->getLVPT())) {
            throw new TokenException('Invalid plugin token sign', 301);
        }

        if ($token->getClaim('jti') !== $inputToken->getClaim('jti')) {
            throw new TokenException("Mismatch 'jti' of plugin and parent tokens", 302);
        }

        return $token;
    }

    public static function getInstance(): ?InputTokenInterface
    {
        return self::$instance;
    }
}