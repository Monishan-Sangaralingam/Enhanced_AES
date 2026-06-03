"""
sbox.py — AES S-Box Construction

This module provides three functions for building AES S-Boxes:
  - build_sbox_algebraic(): Computes the S-Box at runtime via GF(2^8) arithmetic.
  - build_sbox_lut():       Returns the pre-computed S-Box as a hard-coded list.
  - build_inv_sbox(sbox):  Derives the inverse S-Box for use in decryption.

The LUT version is functionally identical to the algebraic version but eliminates
all runtime field arithmetic, making substitution a pure O(1) array lookup.
"""


def _gf_mul(a: int, b: int) -> int:
    """
    Multiply two elements in GF(2^8) modulo the AES irreducible polynomial x^8+x^4+x^3+x+1
    (represented as 0x11B).

    Parameters:
        a (int): First 8-bit field element.
        b (int): Second 8-bit field element.

    Returns:
        int: Product of a and b in GF(2^8), in range [0, 255].
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B          # reduce modulo 0x11B (drop the x^8 term, XOR with 0x1B)
        b >>= 1
    return result


def _gf_inv(a: int) -> int:
    """
    Compute the multiplicative inverse of 'a' in GF(2^8).

    The inverse is found by repeated squaring (exponentiation to the 254th power,
    since every non-zero element satisfies a^255 = 1 in GF(2^8)).
    Special case: the inverse of 0x00 is defined as 0x00 per the AES specification.

    Parameters:
        a (int): An 8-bit field element.

    Returns:
        int: Multiplicative inverse of a in GF(2^8), or 0 if a == 0.
    """
    if a == 0:
        return 0
    result = 1
    base = a
    exp = 254          # a^(2^8 - 2) = a^(-1) by Fermat's little theorem in GF(2^8)
    while exp > 0:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


def _affine_transform(b: int) -> int:
    """
    Apply the AES affine transformation over GF(2) to byte 'b'.

    Per FIPS 197 Section 5.1.1, each output bit i is:
        s_i = b_i XOR b_{(i+4) mod 8} XOR b_{(i+5) mod 8}
                  XOR b_{(i+6) mod 8} XOR b_{(i+7) mod 8} XOR c_i
    where c = 0x63 (the affine constant).

    This is computed here bit-by-bit to exactly match the specification.

    Parameters:
        b (int): The 8-bit multiplicative inverse to transform.

    Returns:
        int: The transformed byte in range [0, 255].
    """
    c = 0x63  # affine constant from the AES specification
    result = 0
    for i in range(8):
        # Extract relevant bits
        bi     = (b >> i) & 1
        bi4    = (b >> ((i + 4) % 8)) & 1
        bi5    = (b >> ((i + 5) % 8)) & 1
        bi6    = (b >> ((i + 6) % 8)) & 1
        bi7    = (b >> ((i + 7) % 8)) & 1
        ci     = (c >> i) & 1
        s_i = bi ^ bi4 ^ bi5 ^ bi6 ^ bi7 ^ ci
        result |= (s_i << i)
    return result


def build_sbox_algebraic() -> list:
    """
    Compute the AES S-Box at runtime using GF(2^8) arithmetic.

    For each byte value v in [0, 255]:
      1. Compute the multiplicative inverse in GF(2^8) (inv(0)=0 per spec).
      2. Apply the AES affine transformation.

    Parameters:
        None

    Returns:
        list: A 256-element list of ints representing the AES SubBytes S-Box.
    """
    sbox = []
    for i in range(256):
        inv = _gf_inv(i)
        sbox.append(_affine_transform(inv))
    return sbox


def build_sbox_lut() -> list:
    """
    Return the pre-computed AES S-Box as a hard-coded lookup table (LUT).

    This is functionally identical to the algebraic version (build_sbox_algebraic)
    but avoids all runtime GF(2^8) arithmetic. Substitution becomes a single array
    index operation — O(1) with very low constant — making it significantly faster
    when encrypting large data.

    Parameters:
        None

    Returns:
        list: A 256-element list of ints representing the AES SubBytes S-Box.
    """
    # Standard AES S-Box (FIPS 197, Figure 7), row-major order.
    # Row i contains S-Box values for inputs 0xi0 through 0xiF.
    return [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]


def build_inv_sbox(sbox: list) -> list:
    """
    Derive the inverse S-Box from a given forward S-Box.

    For each pair (i, sbox[i]), sets inv_sbox[sbox[i]] = i, effectively
    reversing the substitution for use in decryption (InvSubBytes).

    Parameters:
        sbox (list): A 256-element forward S-Box.

    Returns:
        list: A 256-element inverse S-Box.
    """
    inv = [0] * 256
    for i, s in enumerate(sbox):
        inv[s] = i
    return inv
