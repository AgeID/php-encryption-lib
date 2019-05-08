<?php

use AgeId\EncryptionHelper;
use PHPUnit\Framework\TestCase;

class EncryptionHelperTest extends TestCase
{
    private $alphaNumericRange = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private $fullRange = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`-=[]\\;',./~!@#$%^&*()_+{}|:\"<>?";
    private $hash = "eyJzYWx0IjoiZUdsNGJIWlNSRGRQV1RSV1JXUnViV2c0TVU1R1FUMDkiLCJlbmNyeXB0ZWQiOiJVQ0NFVUhTb3RHYksrMlh0bDdKSy9BPT0iLCJtYWMiOiI0YzdjYzFmZWNhY2QzYmY2NzczMzM4MGE0MWQzNjExYWMzZmI2ODBlMWY0YjU4NGQ1MDVlNzFjODg1M2QzZjZkIn0=";
    private $jsonHash = "eyJzYWx0IjoiUnk4eFpuZHlNRTk1ZWxKSWRYZFJaMXBDYVZSVWR6MDkiLCJlbmNyeXB0ZWQiOiJJZ1FkRXNkTmIxeEdDUEJldU5BUjJnPT0iLCJtYWMiOiJhMGQwZjhjOWY4ZWRlMjIyOGQwZjQ3ZWQ4ODMyZTU1ZGI4MDY0YzcxODdjODVlMTBmYzhiYjk4ZGQxZmMxMDRiIn0=";

    const DEFAULT_TEXT = "somePass";
    const DEFAULT_PASS = "someText";
    const DEFAULT_SALT = "Rj2/dM5XZ8QTuw/Z2RzjDQ==";

    /**
     * @test
     */
    public function EmptyTextTest()
    {
        $expected = "eyJzYWx0IjoiVW1veUwyUk5OVmhhT0ZGVWRYY3ZXakpTZW1wRVVUMDkiLCJlbmNyeXB0ZWQiOiJEMzdzcFlPV1IrMmFRbFZSVzMxMGNBPT0iLCJtYWMiOiI3N2UwZTU3MjMwNjRiYWI5YzUwZjlmODcyZjkwNDBkZDFiMDY5OTU4MjM0NTJjZjNhNTFhMDJlM2EzMTNmNDJmIn0=";
        $this->AssertEncryptionIsValid('', self::DEFAULT_PASS, self::DEFAULT_SALT, $expected);
    }

    /**
     * @test
     */
    public function NoSaltTest()
    {
        $this->AssertEncryptionIsValid(self::DEFAULT_TEXT, self::DEFAULT_PASS);
    }

    /**
     * @test
     */
    public function AlphanumericRangeTextTest()
    {
        $expected = "eyJzYWx0IjoiVW1veUwyUk5OVmhhT0ZGVWRYY3ZXakpTZW1wRVVUMDkiLCJlbmNyeXB0ZWQiOiJ4RTQ0Q1EvY3FBc3JwQ3lyZ0JRSXZLeEh5YjhEcUNpbjRKNnF1aFdwKzFTSkN2eXpGNThJZnpaYVkwV3N2ODhadGpBT29nRkJPMFZ2ZzhzUll5N3g3dz09IiwibWFjIjoiYWFhNDgwNWVhMWQ5NDMwZmMzMjJkMGNiODY2ODlmYTI0NGYwNjJlYmIyZWMzM2FlNjlkNDYwMzAxNDRiZjI4ZSJ9";
        $this->AssertEncryptionIsValid($this->alphaNumericRange, self::DEFAULT_PASS, self::DEFAULT_SALT, $expected);
    }

    /**
     * @test
     */
    public function AlphanumericRangePassTest()
    {

        $expected = "eyJzYWx0IjoiVW1veUwyUk5OVmhhT0ZGVWRYY3ZXakpTZW1wRVVUMDkiLCJlbmNyeXB0ZWQiOiJMZ0U4L3BydWR4aGFBWkQ2R05Od1l3PT0iLCJtYWMiOiI2ODlhMzdjYTM2MjAwNjkxNTNjMWEzZThlMDgwNWNjMzM0NGFlMmEwZDY0MzliNGFhOGM0MmQxZGFkZDhkZTM4In0=";
        $this->AssertEncryptionIsValid(self::DEFAULT_TEXT, $this->alphaNumericRange, self::DEFAULT_SALT, $expected);
    }

    /**
     * @test
     */
    public function AlphanumericRangeSaltTest()
    {
        $expected = "eyJzYWx0IjoiWVdKalpHVm1aMmhwYW10c2JXNXZjSEZ5YzNSMWRuZDRlWHBCUWtORVJVWkhTRWxLUzB4TlRrOVFVVkpUVkZWV1YxaFpXakF4TWpNME5UWTNPRGs9IiwiZW5jcnlwdGVkIjoibDY4dFJUc1NLeVdNRHFwR2xQWlM5dz09IiwibWFjIjoiM2VjYmY5MzliMmE1YjQxYmU0MWQwNTc0OTVhNjIxYTk5YTNlZjg4NmFkNTRkNTEwNWEyZmUwMWQ0NTA0YjJiYiJ9";
        $this->AssertEncryptionIsValid(self::DEFAULT_TEXT, self::DEFAULT_PASS, $this->alphaNumericRange, $expected);
    }

    /**
     * @test
     */
    public function FullRangeTextTest()
    {
        $expected = "eyJzYWx0IjoiVW1veUwyUk5OVmhhT0ZGVWRYY3ZXakpTZW1wRVVUMDkiLCJlbmNyeXB0ZWQiOiJ4RTQ0Q1EvY3FBc3JwQ3lyZ0JRSXZLeEh5YjhEcUNpbjRKNnF1aFdwKzFTSkN2eXpGNThJZnpaYVkwV3N2ODhaMXN3QmJwcGRudzlRbVd4c2duTXo2aTUvYVZicDFPbmQ2cHhDNFBEN0VWcnV3Q1RDa3ViUXRCRGtwR0FrY1lJbSIsIm1hYyI6ImMzMjExNTA4MGUyZTgyODc1ZGI5YjNmMTg4ODQ4ZDI0OGYxZGVmMDFhMWE3NTY0MmIwZDhmNjM5YzExMjllM2MifQ==";
        $this->AssertEncryptionIsValid($this->fullRange, self::DEFAULT_PASS, self::DEFAULT_SALT, $expected);
    }

    /**
     * @test
     */
    public function FullRangePassTest()
    {
        $expected = "eyJzYWx0IjoiVW1veUwyUk5OVmhhT0ZGVWRYY3ZXakpTZW1wRVVUMDkiLCJlbmNyeXB0ZWQiOiJDOHV5Q3FrcFM5L29ZVGJ1TmtiUHFRPT0iLCJtYWMiOiI0OTQyM2RiOGFhZGZmYjJiNWNmMDFmZDNjNzAyNGFmNTRlMWVjMDkyYjFlY2JhNGVlMzQwODAzYWVjYTA0MmE5In0=";
        $this->AssertEncryptionIsValid(self::DEFAULT_TEXT, $this->fullRange, self::DEFAULT_SALT, $expected);
    }

    /**
     * @test
     */
    public function FullRangeSaltTest()
    {
        $expected = "eyJzYWx0IjoiWVdKalpHVm1aMmhwYW10c2JXNXZjSEZ5YzNSMWRuZDRlWHBCUWtORVJVWkhTRWxLUzB4TlRrOVFVVkpUVkZWV1YxaFpXakF4TWpNME5UWTNPRGxnTFQxYlhWdzdKeXd1TDM0aFFDTWtKVjRtS2lncFh5dDdmWHc2SWp3K1B3PT0iLCJlbmNyeXB0ZWQiOiJRc3NrRXBBN1c2YjlsOHg1c3A3K1JnPT0iLCJtYWMiOiIyMmM2NzkzZWFjYjI5OGM0YjI2N2NhYzdkMjgzZDc1YzcwNGJkOGU3NDI5MmZjOGE2NTZkODU0MGJlMWY5NjM0In0=";
        $this->AssertEncryptionIsValid(self::DEFAULT_TEXT, self::DEFAULT_PASS, $this->fullRange, $expected);
    }

    /**
     * @test
     */
    public function testDecrypt()
    {
        $decryptor = new EncryptionHelper('GrtcRtReJgYcrKeJQ1GolkYiLksPlM84');

        $decrypted = $decryptor->decrypt('eyJzYWx0IjoiUVVWUmIxQk1VSEp4VFhsMGJrTmhlV3AyTkRSQlFUMDkiLCJlbmNyeXB0ZWQiOiJsMHZmMThkeHBEeFQ0WkhIblliWW1tTXJrM3ltMWwzQ3h5NEVsekVPUGVyd1pYcGo4QXNvakM0VU4xNkFaZXU1IiwibWFjIjoiYjIzYmY4ZDM4MDhkMjdlZTIxYmRiZmJkZmMyYmZkNThmYjRiOWM0OGQxZGNiZDFlODJlYzk1ZDcwYWZhZjM2NSJ9');
        print_r($decrypted);exit;
        $this->assertTrue($decrypted == self::DEFAULT_TEXT);
    }

    /**
     * @test
     */
    public function testDecryptJson()
    {
        $decryptor = new EncryptionHelper(self::DEFAULT_PASS);

        $decrypted = $decryptor->decrypt($this->jsonHash);
        $payload = json_decode($decrypted, true);
        $this->assertTrue( is_array($payload));
        $this->assertArrayHasKey("key", $payload);
    }

    /**
     * @test
     */
    public function testGeneratedSaltFromEncryptedPayload()
    {
        $payloadArray = json_decode(base64_decode($this->jsonHash), true);
        $payloadSalt = base64_decode(base64_decode($payloadArray['salt']));
        $salt1 = bin2hex(mb_convert_encoding($payloadSalt, 'UTF-8'));
        $salt2 = bin2hex($payloadSalt);

        $this->assertNotEquals($salt1, $salt2);
    }

    private function AssertEncryptionIsValid($clearText, $pass, $salt = null, $expected = null, $apiVersion = 'v2')
    {
        $encrypter = new EncryptionHelper($pass, $salt, $apiVersion);

        $encodedPayload = $encrypter->encrypt($clearText);
        $decryptedText = $encrypter->decrypt($encodedPayload);

        $this->assertEquals($clearText, $decryptedText);

        if( $expected ) {
            $this->assertEquals($expected, $encodedPayload);
        }
    }
}