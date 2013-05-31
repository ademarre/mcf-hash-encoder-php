Binary MCF Encoding in PHP
==========================

The **McfHash** class is a PHP implementation of [Binary Modular Crypt Format][bmcf] (BMCF) encoding. Only the [Bcrypt BMCF definition][bcryptbmcf] is implemented.

[bmcf]:         https://github.com/ademarre/binary-mcf "Binary Modular Crypt Format"
[bcryptbmcf]:   https://github.com/ademarre/binary-mcf#bcrypt-bmcf-definition "Bcrypt BMCF Definition"

You can use <code>McfHash::decode()</code> to convert a Bcrypt hash from the usual 60-character notation to its compact 40-byte binary form.

```php
$hash = '$2y$14$i5btSOiulHhaPHPbgNUGdObga/GC.AVG/y5HHY1ra7L0C9dpCaw8u'; // 60 bytes ACSII
$mcfEncoder = new McfHash();
$binaryHash = $mcfEncoder->decode($hash); // 40 bytes binary
```

Use <code>McfHash::encode()</code> to reconstruct the hash.

```php
$hash = $mcfEncoder->encode($binaryHash);
// $2y$14$i5btSOiulHhaPHPbgNUGdObga/GC.AVG/y5HHY1ra7L0C9dpCaw8u
```
