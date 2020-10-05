<?php
/**
 * Created for plugin-core-macros
 * Date: 22.09.2020
 * @author Timur Kasumov (XAKEPEHOK)
 */

namespace Leadvertex\Plugin\Components\Token;


use Lcobucci\JWT\Token;
use Leadvertex\Plugin\Components\Registration\Registration;

interface InputTokenInterface
{

    public function __construct(string $token);

    public function getId(): string;

    public function getCompanyId(): string;

    public function getBackendUri(): string;

    public function getRegistration(): Registration;

    public function getInputToken(): Token;

    public function getOutputToken(): Token;

}