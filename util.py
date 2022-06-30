def big_to_little8(num: int) -> int:
    """
    Convert 8-byte big endian integer to little endian integer to work with bitwise operations.

    Parameters
    ----------
    num : int
        Integer to be converted
    
    Returns
    -------
    int
        Converted integer
    """
    return int.from_bytes(num.to_bytes(8, 'big'), 'little')

def rotl8(num: int, bits: int) -> int:
    """
    Bitwise left-rotate of a 8-byte number.

    Parameters
    ----------
    num : int
        Number to be left-rotated
    bits : int
        Number of bits to be left-rotated
    
    Returns
    -------
    int
        Left-rotated number
    """
    return ((num << bits) & 0xffffffffffffffff) | (num >> (64 - bits))
