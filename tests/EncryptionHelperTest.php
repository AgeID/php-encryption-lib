<?php

use AgeId\EncryptionHelper;
use PHPUnit\Framework\TestCase;

class EncryptionHelperTest extends TestCase
{
    private $password = "UyBr4VkvZgR1uS";
    private $salt = "1c4dd21d7ba43bdd";

    private $clearText = "text clear";
    private $hash = "eyJzYWx0IjoiTVdNMFpHUXlNV1EzWW1FME0ySmtaQT09IiwiZW5jcnlwdGVkIjoiTUgrOG10SjlCU2F3cWY5XC9QN3hwelE9PSIsIm1hYyI6IjRmZWVhNTU1NDdmMjgzYWUwNGFmNDA0NmJjMTM5ZDM1MGFmNGQyNmNmMTUxZmRkNDI2MTI0NmJiMGQxNTJmMDkifQ==";

    /**
     * @test
     */
    public function testDecrypt()
    {
        $decryptor = new EncryptionHelper($this->password);
        $hash      = $decryptor->encrypt($this->clearText);
        $decrypted = $decryptor->decrypt($hash);
        $this->assertTrue($decrypted == $this->clearText);
    }

    /**
     * @test
     */
    public function testEncrypt()
    {
        //used a predefined salt
        $encrypter = new EncryptionHelper($this->password, $this->salt);
        $encrypted = $encrypter->encrypt($this->clearText);
        $this->assertTrue($encrypted == $this->hash);

    }
}
