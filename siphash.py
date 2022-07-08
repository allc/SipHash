from typing import List, Tuple
from util import big_to_little8, rotl8


class SipHash:

    # TODO: Change ways to pass parameters in a more object-oriented way.
    
    """
    Implemented following the algorithm in (Aumasson and Bernstein, 2012).

    Aumasson, JP., Bernstein, D.J. (2012). SipHash: A Fast Short-Input PRF.
    In: Galbraith, S., Nandi, M. (eds) Progress in Cryptology - INDOCRYPT 2012.
    INDOCRYPT 2012. Lecture Notes in Computer Science, vol 7668.
    Springer, Berlin, Heidelberg. https://doi.org/10.1007/978-3-642-34931-7_28
    """

    def __init__(self, key: int, message: bytes, c=2, d=4) -> None:
        """
        Initialise SipHash with a key and message.

        Parameters
        ----------
        key : int
            16-byte big-endian key
        message : bytes
            Message to be hashed in big-endian bytes
        c : int
            Number of compression rounds
        d : int
            Number of finalization round
        """
        self.key = key
        self.message = message
        self.c = c
        self.d = d
        self.hash = None

    def get_hash(self) -> int:
        """
        Return hash of the message hashed with the key.

        Return from saved value if the hash has been calculated, or calculate the hash value and save it and return.

        Returns
        -------
        int
            Hash value in little-endian
        """
        if self.hash is None:
            k0, k1 = self._encode_key(self.key)
            internal_state = self._initialise_internal_state(k0, k1)
            internal_state = self._compress(self.message, internal_state)
            self.hash = self._finalise(internal_state)
        return self.hash

    def hexdigest(self) -> str:
        """
        Return the hex string of the hash.

        Returns
        -------
        str
            Hex string of the hash
        """
        return hex(self.get_hash())[2:]

    def _encode_key(self, key: int) -> Tuple[int, int]:
        """
        Encode 16-byte key into 8-byte k0 and k1.

        Parameters
        ----------
        key : int
            16-byte big-endian key

        Returns
        -------
        (bytes, bytes)
            Tuple of k0 and k1
        """
        return (big_to_little8(key >> 8 * 8), big_to_little8(key & 0xffffffffffffffff))

    def _initialise_internal_state(self, k0: int, k1: int) -> Tuple[int, int, int, int]:
        """
        Initialise internal state v0, v1, v2, v3.

        Parameters
        ----------
        k0 : int
            8-byte k0
        k1 : int
            8-byte k1

        Returns
        -------
        (int, int, int, int)
            Internal state v0, v1, v2, v3
        """
        c1 = 0x736f6d6570736575
        c2 = 0x646f72616e646f6d
        c3 = 0x6c7967656e657261
        c4 = 0x7465646279746573
        v0 = k0 ^ int(c1)
        v1 = k1 ^ int(c2)
        v2 = k0 ^ int(c3)
        v3 = k1 ^ int(c4)
        return (v0, v1, v2, v3)

    def _compress(self, message: bytes, internal_state: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
        """
        Compress the message into internal state.

        Parameters
        ----------
        message : bytes
            Message to be hashed in big endian bytes
        internal_state : (int, int, int, int)
            Internal state v0, v1, v2, v3

        Returns
        -------
        (int, int, int, int)
            Internal state with message compressed into
        """
        words = self._message_to_words(message)

        v0, v1, v2, v3 = internal_state
        for word in words:
            v3 ^= word
            for _ in range(self.c):
                v0, v1, v2, v3 = self._sipround((v0, v1, v2, v3))
            v0 ^= word
        
        return (v0, v1, v2, v3)

    def _message_to_words(self, message: bytes) -> List[int]:
        """
        Parse message into words

        Parameters
        ----------
        message : bytes
            Message to be hashed in big endian bytes

        Returns
        -------
        [int]
            Message parsed into little-endian words
        """
        message_length = len(message)
        padding_length = (message_length + 1) % 8
        message = message + b'\x00' * padding_length + (message_length % 256).to_bytes(1, 'little')
        return [int.from_bytes(message[i: i + 8], 'little') for i in range(0, len(message), 8)]

    def _sipround(self, internal_state: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
        """
        SipRound to transform internal state.

        Parameters
        ----------
        internal_state : (int, int, int, int)
            Internal state v0, v1, v2, v3

        Returns
        -------
        (int, int, int, int)
            Internal state v0, v1, v2, v3 after SipRound transform
        """
        v0, v1, v2, v3 = internal_state

        v0 = (v0 + v1) & 0xffffffffffffffff
        v1 = rotl8(v1, 13)
        v1 ^= v0
        v0 = rotl8(v0, 32)
        v2 = (v2 + v3) & 0xffffffffffffffff
        v3 = rotl8(v3, 16)
        v3 ^= v2
        v2 = (v2 + v1) & 0xffffffffffffffff
        v1 = rotl8(v1, 17)
        v1 ^= v2
        v2 = rotl8(v2, 32)
        v0 = (v0 + v3) & 0xffffffffffffffff
        v3 = rotl8(v3, 21)
        v3 ^= v0

        return (v0, v1, v2, v3)

    def _finalise(self, internal_state: Tuple[int, int, int, int]) -> int:
        """
        Finalise SipHash

        Parameters
        ----------
        internal_state : (int, int, int, int)
            Internal state before finalise

        Returns
        -------
        int
            SipHash result in little-endian representation
        """
        v0, v1, v2, v3 = internal_state
        v2 ^= 0xff
        for _ in range(self.d):
            v0, v1, v2, v3 = self._sipround((v0, v1, v2, v3))
        return v0 ^ v1 ^ v2 ^ v3
