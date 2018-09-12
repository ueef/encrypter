<?php
declare(strict_types=1);

namespace Ueef\Encrypter\Interfaces;

interface EncrypterInterface
{
    public function encrypt(string $message): string;
    public function decrypt(string $message): string;
}

