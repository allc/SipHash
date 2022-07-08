import unittest
import binascii
from siphash import SipHash


class TestSipHash(unittest.TestCase):

    def setUp(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        message = binascii.unhexlify(b'000102030405060708090a0b0c0d0e')
        self.siphash = SipHash(key, message)

    def test_encode_key(self):
        key = 0x000102030405060708090a0b0c0d0e0f
        k0 = 0x0706050403020100
        k1 = 0x0f0e0d0c0b0a0908
        self.assertEqual(self.siphash._encode_key(key), (k0, k1))

    def test_initialise_internal_state(self):
        v0 = 0x7469686173716475
        v1 = 0x6b617f6d656e6665
        v2 = 0x6b7f62616d677361
        v3 = 0x7b6b696e727e6c7b
        self.assertEqual(self.siphash._initialise_internal_state(0x0706050403020100, 0x0f0e0d0c0b0a0908), (v0, v1, v2, v3))

    def test_compress(self):
        v0 = 0x7469686173716475
        v1 = 0x6b617f6d656e6665
        v2 = 0x6b7f62616d677361
        v3 = 0x7b6b696e727e6c7b
        v0_compression = 0x3c85b3ab6f55be51
        v1_compression = 0x414fc3fb98efe374
        v2_compression = 0xccf13ea527b9f4bd
        v3_compression = 0x5293f5da84008f82
        message = binascii.unhexlify(b'000102030405060708090a0b0c0d0e')
        self.assertEqual(self.siphash._compress(message, (v0, v1, v2, v3)), (v0_compression, v1_compression, v2_compression, v3_compression))

    def test_message_to_words(self):
        message = binascii.unhexlify(b'000102030405060708090a0b0c0d0e')
        self.assertListEqual(self.siphash._message_to_words(message), [0x0706050403020100, 0x0f0e0d0c0b0a0908])

    def test_sipround(self):
        v0 = 0x7469686173716475
        v1 = 0x6b617f6d656e6665
        v2 = 0x6b7f62616d677361
        v3 = 0x7c6d6c6a717c6d7b
        v0_sipround2 = 0x4d07749cdd0858e0
        v1_sipround2 = 0x0d52f6f62a4f59a4
        v2_sipround2 = 0x634cb3577b01fd3d
        v3_sipround2 = 0xa5224d6f55c7d9c8
        sipround1 = self.siphash._sipround((v0, v1, v2, v3))
        sipround2 = self.siphash._sipround(sipround1)
        self.assertEqual(sipround2, (v0_sipround2, v1_sipround2, v2_sipround2, v3_sipround2))

    def test_finalise(self):
        v0 = 0x3c85b3ab6f55be51
        v1 = 0x414fc3fb98efe374
        v2 = 0xccf13ea527b9f4bd
        v3 = 0x5293f5da84008f82
        h = 0xa129ca6149be45e5
        self.assertEqual(self.siphash._finalise((v0, v1, v2, v3)), h)

    def test_get_hash(self):
        self.assertEqual(self.siphash.get_hash(), 0xa129ca6149be45e5)

    def test_get_hash_caching(self):
        self.siphash.get_hash()
        self.assertEqual(self.siphash.hash, 0xa129ca6149be45e5)

    def test_hexdigest(self):
        self.assertEqual(self.siphash.hexdigest(), 'a129ca6149be45e5')

if __name__ == '__main__':
    unittest.main()
