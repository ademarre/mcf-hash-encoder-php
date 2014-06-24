Binary MCF Encoding in PHP
==========================

The **McfHash** class is a PHP implementation of [Binary Modular Crypt Format][bmcf] (BMCF) encoding. Only the [Bcrypt BMCF definition][bcryptbmcf] is implemented.

[bmcf]:         https://github.com/ademarre/binary-mcf "Binary Modular Crypt Format"
[bcryptbmcf]:   https://github.com/ademarre/binary-mcf#bcrypt-bmcf-definition "Bcrypt BMCF Definition"

You can use the <code>decode()</code> function to convert a Bcrypt hash from the usual 60-character notation to its compact 40-byte binary form.

```php
$hash = '$2y$14$i5btSOiulHhaPHPbgNUGdObga/GC.AVG/y5HHY1ra7L0C9dpCaw8u'; // $hash is 60 bytes ACSII.
$mcfEncoder = new McfHash();
$binaryHash = $mcfEncoder->decode($hash); // $binaryHash is now 40 bytes binary.
```

Use the <code>encode()</code> function to reconstruct the hash.

```php
$binaryHash = $mcfEncoder->encode($binaryHash); // $binaryHash is now 60 bytes ACSII once again ($2y$14$i5btSOiulHhaPHPbgNUGdObga/GC.AVG/y5HHY1ra7L0C9dpCaw8u).
```
