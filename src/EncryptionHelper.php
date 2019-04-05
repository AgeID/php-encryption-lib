<?php

namespace AgeId;

/**
 * Symmetric encryption & decryption using AES256 for integration with AgeID
 */
class EncryptionHelper
{

    const CIPHER = 'aes-256-cbc';
    const ENCRYPTION_ITERATIONS = [
        'v1' => 32768,
        'v2' => 1024
    ];

    private $pass;
    private $salt;
    private $iterations;

    /**
     * Set the salt & password key
     *
     * @param      $saltKey string salt key
     * @param      $passKey string password key
     * @param      $ageIdApiVersion decides the number of iterations
     */
    function __construct($passKey, $saltKey = null, $ageIdApiVersion = "v2")
    {
        $this->pass = $passKey;
        $this->salt = $saltKey;
        $this->iterations = self::ENCRYPTION_ITERATIONS[$ageIdApiVersion] ?? end(array_values(self::ENCRYPTION_ITERATIONS));
    }


    /**
     * Generate the HMAC signature using SHA256 algorithm
     *
     * @param $salt
     * @param $value
     *
     * @return string
     */
    private function hash($salt, $value)
    {
        return hash_hmac('sha256', $salt . $value, $this->pass);
    }


    /**
     * @param $clearBytes
     * @param $passBytes
     * @param $saltBytes
     *
     * @return string
     */
    private function AESEncryptBytes($clearBytes, $passBytes, $saltBytes)
    {
        // create a key from the password and salt
        $key     = new Rfc2898DeriveBytes($passBytes, $saltBytes, $this->iterations);
        $derived = $key->derived();
        //AES encryption
        $encryptedBytes = openssl_encrypt($clearBytes, self::CIPHER, $derived->key, null, $derived->iv);

        return $encryptedBytes;

    }

    /**
     * Encrypt text based on password and salt key using AES256
     *
     * @param $clearText string text to encrypt
     *
     * @return string   encrypted test
     * @throws AgeIdException
     */
    public function encrypt($clearText)
    {
        //generate random salt
        if (is_null($this->salt)) {
            $this->salt = random_bytes(openssl_cipher_iv_length(self::CIPHER));
        }

        if( mb_strlen($this->salt, '8bit') < 16 ) {
            throw new AgeIdException('Salt should be at least 16 Bytes!');
        }

        $clearText = mb_convert_encoding($clearText, 'UTF-8');
        $pass      = mb_convert_encoding($this->pass, 'UTF-8');
        $salt      = mb_convert_encoding($this->salt, 'UTF-8');

        $encrypted = $this->AESEncryptBytes($clearText, $pass, $salt);

        if ($encrypted === false) {
            throw new AgeIdException('Could not encrypt the data.');
        }

        // Once we get the encrypted value we'll go ahead and base64_encode the input
        // vector and create the MAC for the encrypted value so we can then verify
        // its authenticity. Then, we'll JSON the data into the "payload" array.

        $salt = base64_encode($salt);

        $mac = $this->hash($salt, $encrypted);


        $json = json_encode(compact('salt', 'encrypted', 'mac'));


        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new AgeIdException('Could not encrypt the data.');
        }
        return base64_encode($json);


    }


    /**
     * Get the JSON array from the given payload.
     *
     * @param  string $payload
     *
     * @return array
     *
     * @throws AgeIdException
     */
    private function getJsonPayload($payload)
    {
        $payload = json_decode(base64_decode($payload), true);

        // If the payload is not valid JSON or does not have the proper keys set we will
        // assume it is invalid and bail out of the routine since we will not be able
        // to decrypt the given value. We'll also check the MAC for this encryption.
        if (!$this->validPayload($payload)) {
            throw new AgeIdException('The payload is invalid.');
        }
        if (!$this->validMac($payload)) {
            throw new AgeIdException('The MAC is invalid.');
        }
        return $payload;
    }

    /**
     * Verify that the encryption payload is valid.
     *
     * @param  mixed $payload
     *
     * @return bool
     */
    private function validPayload($payload)
    {
        return is_array($payload) && isset(
                $payload['salt'], $payload['encrypted'], $payload['mac']
            );
    }

    /**
     * Determine if the MAC for the given payload is valid.
     *
     * @param  array $payload
     *
     * @return bool
     * @throws \Exception
     */
    private function validMac($payload)
    {
        $calculated = $this->calculateMac($payload, $bytes = random_bytes(16));
        return hash_equals(
            hash_hmac('sha256', $payload['mac'], $bytes, true), $calculated
        );
    }

    /**
     * Calculate the hash of the given payload.
     *
     * @param  array  $payload
     * @param  string $bytes
     *
     * @return string
     */
    private function calculateMac($payload, $bytes)
    {
        return hash_hmac(
            'sha256', $this->hash($payload['salt'], $payload['encrypted']), $bytes, true
        );
    }

    /**
     * AES decrypt
     *
     * @param $cryptText
     * @param $passBytes
     * @param $saltBytes
     *
     * @return string
     */
    private function AESDecryptBytes($cryptText, $passBytes, $saltBytes)
    {
        $key     = new Rfc2898DeriveBytes($passBytes, $saltBytes,  $this->iterations);
        $derived = $key->derived();

        $decrypted = openssl_decrypt($cryptText, self::CIPHER, $derived->key, null, $derived->iv);

        return mb_convert_encoding($decrypted, 'UTF-8');
    }

    /**
     * Decrypt text based on password and embedded salt key using AES256
     *
     * @param $encryptedText string encrypted message
     *
     * @return string   decrypted message
     * @throws AgeIdException
     */
    public function decrypt($encryptedText)
    {
        $pass = mb_convert_encoding($this->pass, 'UTF-8');

        $payload = $this->getJsonPayload($encryptedText);


        $payload['salt'] = base64_decode($payload['salt']);
        $payload['salt'] = mb_convert_encoding($payload['salt'], 'UTF-8');

        $decrypted = $this->AESDecryptBytes($payload['encrypted'], $pass, $payload['salt']);

        return $decrypted;
    }

}