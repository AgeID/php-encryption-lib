AgeID Encryption Helper
=================

AES256 encryption and decryption helper for AgeID using an embedded random salt key.  

The implementation is based on Laravel Encrypter.

Requirements: PHP 7

For PHP 5.6 compatibility, please install the PHP 5.x polyfill for random_bytes() :

    composer require paragonie/random_compat
    
    
## Change Log

List of releases and changes, with the latest at the top:
  * v2.1
    * fixed compatibility with php 5.6 
    * removed utf8 conversion for salt that was causing entropy loss
  * v2.0 **[!] Should be used for v2 endpoint and forward  [!]**
    * The number of iterations in EncryptionHelper is set by setting the version number on Instantiation; if it not set it will choose the latest version
    * Only allow salt with at least 16 Bytes
    * reduced the number of iterations to be 1024 by default
  * [first-release]
  
Usage
---

__Installation__

Use composer to install the package 

    composer require ageid/encryption-helper
    
or download the the package and include the _src/*_ files in your project.

__Encryption__

 By default, it uses a random salt key, but it can be specified in the constructor.
 
 
Example:

        use AgeId\EncryptionHelper;


        $password = "8d6ea4d3e6f8c4f8641516baa5e42b85";
        
        $text = "text clear";
        
        $encrypter = new EncryptionHelper($password);
        $encrypted = $encrypter->encrypt($text);

        echo $encrypted;
  
__Decryption__

Example:

        use AgeId\EncryptionHelper;

        $password = "8d6ea4d3e6f8c4f8641516baa5e42b85";
        
        
        $hash = "eyJzYWx0IjoiVWluUHJUOFwvZVQ5REZUZ1wvUHo4NyIsImVuY3J5cHRlZCI6IjJxbzgzcmRsMWNWQ0VJTHVjazBJSFE9PSIsIm1hYyI6IjJmYWM3NWY4ZTk4NmI1MGYwMzgwYTcxYTgwMTA3NmNiM2Y3Y2MwYzBkZDNkNWIwOGYxNTI2ZTkwYTRlMTdkZjgifQ==";
        
        $decryptor = new EncryptionHelper($password);
        $decrypted = $decryptor->decrypt($hash);

        echo $decrypted;

Tests
---

In order to run the tests, please run in the package folder: 

    composer install
    phpunit
    
    

    
