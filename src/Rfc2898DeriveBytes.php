<?php
namespace AgeId;

/**
 * Implementation of .NET Rfc2898DeriveBytes class
 */
class Rfc2898DeriveBytes
{
    private $password;
    private $salt;
    private $iterations;
    private $cipher;


    /**
     * Initialization
     * @param        $password
     * @param        $salt
     * @param int    $iterations
     * @param string $cipher
     */
    public function __construct($password, $salt, $iterations = 32768, $cipher = 'aes-256-cbc')
    {
        $this->password   = $password;
        $this->salt       = $salt;
        $this->iterations = $iterations;
        $this->cipher     = $cipher;

    }

    /**
     * Return key size based on cipher
     * @return int
     */
    private function getKeySize()
    {
        if (preg_match("/([0-9]+)/i", $this->cipher, $matches)) {
            return $matches[1] >> 3;
        }
        return 0;
    }

    /**
     * Return the key/vector as object
     * @return \stdClass
     */
    public function derived()
    {
        $password     = $this->password;
        $salt         = $this->salt;
        $AESKeyLength = $this->getKeySize();
        $AESIVLength  = openssl_cipher_iv_length($this->cipher);
        $pbkdf2       = hash_pbkdf2("SHA1", $password, mb_convert_encoding($salt, 'UTF-8'), $this->iterations, $AESKeyLength + $AESIVLength, true);
        $key          = substr($pbkdf2, 0, $AESKeyLength);
        $iv           = substr($pbkdf2, $AESKeyLength, $AESIVLength);
        $derived      = new \stdClass();
        $derived->key = $key;
        $derived->iv  = $iv;
        return $derived;
    }
}