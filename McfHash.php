<?php
/**
 * (Binary) Modular Crypt Format Hash Encoding
 *
 * @package     mcf-hash-encoder-php
 * @link        https://github.com/ademarre/mcf-hash-encoder-php
 * @author      Andre DeMarre
 * @copyright   2013 Andre DeMarre
 * @license     http://opensource.org/licenses/MIT  MIT
 */

/**
 * Encoding and Decoding of (Binary) Modular Crypt Format hashes
 *
 * The McfHash class offers a compact binary serialization
 * of hash digests which follow the Modular Crypt Format (MCF),
 * a de facto notational convention used by the crypt(3) *nix
 * function, and implemented in several programming languages,
 * including PHP.
 *
 * Example:
 * $2y$14$i5btSOiulHhaPHPbgNUGdObga/GC.AVG/y5HHY1ra7L0C9dpCaw8u
 *
 * For now, only the Bcrypt hash algorithm is supported, but it is
 * expandable to support hashes from other algorithms without
 * affecting existing BMCF hashes.
 *
 * There is a dependency on the Base2n class in
 * {@link https://github.com/ademarre/binary-to-text-php}.
 *
 * @see https://github.com/ademarre/binary-mcf BMCF Specification
 * @see http://pythonhosted.org/passlib/modular_crypt_format.html
 * @see http://en.wikipedia.org/wiki/Crypt_%28C%29
 * @see http://php.net/crypt
 *
 * @package mcf-hash-encoder-php
 */
class McfHash
{
    // 3-bit algorithm identifiers (in the three most significant bits)
    // Our nomenclature here is algoId => scheme
    protected $_algorithms = array(
    //  0x00  => 'blank', // Reserved; perhaps for the implicit DES schemes
        0x20  => '2',
        0x40  => '2a',
        0x60  => '2x',
        0x80  => '2y',
    //  0xA0  => '5',     // Reserved
    //  0xC0  => '6',     // Reserved
    //  0xE0  => 'other', // Reserved for overflow to next 5 bits
    );

    /**
     * Decode an MCF hash into binary form (BMCF)
     *
     * @param   string  $hash   MCF hash
     * @return  string  Compact BMCF of $hash
     *
     * @throws  InvalidArgumentException
     * @throws  RangeException
     * @throws  UnexpectedValueException
     */
    public function decode($hash)
    {
        if (!is_string($hash)) throw new InvalidArgumentException('$hash must be a string');
        if ($hash[0] != '$') throw new RangeException('Unsupported hash algorithm'); // Possibly a DES hash

        $parts = explode('$', $hash, 4);
        $algoIds = array_flip($this->_algorithms);

        if (!isset($parts[2]) || !isset($algoIds[$parts[1]])) {
            throw new RangeException('Unsupported hash algorithm');
        }

        // At this point we know we're working with a Bcrypt hash

        if (strlen($parts[3]) != 53) {
            throw new UnexpectedValueException('Invalid Bcrypt hash');
        }

        $scheme = $parts[1];
        $cost = $parts[2];

        if (strlen($cost) != 2 || !ctype_digit($cost)) {
            throw new UnexpectedValueException('Invalid Bcrypt cost');
        }

        $headerOctet = $algoIds[$scheme] | (intval($cost) & 0x1F);
        $binaryHash = pack('C', $headerOctet);

        $b64 = $this->_getbinaryToTextEncoder($scheme);

        // Decode the salt
        $binaryHash .= $b64->decode(substr($parts[3], 0, 22));

        // Decode the hash digest
        $binaryHash .= $b64->decode(substr($parts[3], 22, 31));

        return $binaryHash;
    }

    /**
     * Encode a BMCF hash into textual notation (MCF)
     *
     * @param   string  $binaryHash BMCF hash
     * @return  string  MCF $binaryHash
     *
     * @throws  InvalidArgumentException
     * @throws  RangeException
     * @throws  UnexpectedValueException
     */
    public function encode($binaryHash)
    {
        if (!is_string($binaryHash) || !isset($binaryHash[12])) {
            throw new InvalidArgumentException('$binaryHash must be a string of at least 13 bytes');
        }

        $octets = unpack('C', $binaryHash[0]);
        $headerOctet = array_shift($octets);

        // Get the algorithm identifier
        $algoId = $headerOctet & 0xE0;
        if (!isset($this->_algorithms[$algoId])) {
            throw new RangeException('Unsupported hash algorithm');
        }
        $scheme = $this->_algorithms[$algoId];

        // At this point we know we're working with a Bcrypt hash

        if (strlen($binaryHash) != 40) {
            throw new UnexpectedValueException('Invalid Bcrypt hash');
        }

        $b64 = $this->_getbinaryToTextEncoder($scheme);

        $cost = sprintf('%02u', $headerOctet - $algoId);
        $salt = $b64->encode(substr($binaryHash, 1, 16));
        $hashDigest = $b64->encode(substr($binaryHash, 17, 23));

        return '$' . $scheme . '$' . $cost . '$' . $salt . $hashDigest;
    }

    protected function _getbinaryToTextEncoder($scheme)
    {
        switch ($scheme) {
            case '2':
            case '2a':
            case '2x':
            case '2y':
                // Bcrypt
                return new Base2n(6, './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', TRUE, TRUE);
            default:
                throw new InvalidArgumentException('No binary-to-text encoder for the requested scheme');
        }
    }
}
