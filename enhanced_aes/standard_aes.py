"""
standard_aes.py — Standard AES-128 (Algebraic S-Box)

This module implements the full AES-128 block cipher using the algebraically
derived S-Box (computed via GF(2^8) arithmetic at startup). It serves as the
baseline for benchmark comparisons against the LUT-optimised enhanced_aes.py.

Mode: ECB (Electronic Codebook) with PKCS#7 padding.
NOTE: ECB mode is used here only for straightforward performance comparison.
      It is NOT recommended for production use because identical plaintext blocks
      produce identical ciphertext blocks, leaking structural information.

Key size: 128 bits (16 bytes) — AES-128 only.
Rounds:   10.

Public API:
  encrypt(plaintext: bytes, key: bytes) -> bytes
  decrypt(ciphertext: bytes, key: bytes) -> bytes
"""

from sbox import build_sbox_algebraic, build_inv_sbox
from utils import key_expansion, pkcs7_pad, pkcs7_unpad, bytes_to_state, state_to_bytes

# ---------------------------------------------------------------------------
# Module-level S-Box initialisation (computed once at import time)
# ---------------------------------------------------------------------------
_SBOX = build_sbox_algebraic()
_INV_SBOX = build_inv_sbox(_SBOX)

# ---------------------------------------------------------------------------
# Pre-computed MixColumns lookup tables for GF(2^8) multiplications by 2 and 3,
# and their inverses by 9, 11, 13, 14 — avoids per-byte calls to _gf_mul.
# ---------------------------------------------------------------------------

def _xtime(a: int) -> int:
    """Multiply 'a' by 2 in GF(2^8) (single left-shift with conditional reduction)."""
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _gf_mul(a: int, b: int) -> int:
    """
    Multiply two elements in GF(2^8) using the peasant's algorithm.

    Parameters:
        a (int): First field element [0, 255].
        b (int): Second field element [0, 255].

    Returns:
        int: Product in GF(2^8).
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result & 0xFF


# ---------------------------------------------------------------------------
# AES Core Transformations
# ---------------------------------------------------------------------------

def sub_bytes(state: list) -> list:
    """
    Apply the AES SubBytes substitution using the algebraic S-Box.

    Each byte in the 4×4 state is independently replaced by the S-Box value
    at the corresponding index.  This is the non-linear step that provides
    confusion in the cipher.

    Parameters:
        state (list): 4×4 AES state matrix (list of 4 rows, each a list of 4 ints).

    Returns:
        list: New 4×4 state with every byte substituted.
    """
    return [[_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state: list) -> list:
    """
    Apply InvSubBytes using the inverse algebraic S-Box (for decryption).

    Parameters:
        state (list): 4×4 AES state matrix.

    Returns:
        list: 4×4 state with inverse substitution applied.
    """
    return [[_INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(state: list) -> list:
    """
    Apply AES ShiftRows: cyclically left-shift each row by its row index.

    Row 0: no shift.
    Row 1: shift left by 1.
    Row 2: shift left by 2.
    Row 3: shift left by 3.

    Parameters:
        state (list): 4×4 AES state matrix.

    Returns:
        list: New state with rows shifted.
    """
    return [state[r][r:] + state[r][:r] for r in range(4)]


def inv_shift_rows(state: list) -> list:
    """
    Apply AES InvShiftRows: cyclically right-shift each row by its row index.

    Parameters:
        state (list): 4×4 AES state matrix.

    Returns:
        list: New state with rows right-shifted.
    """
    return [state[r][(4 - r) % 4:] + state[r][:(4 - r) % 4] for r in range(4)]


def mix_columns(state: list) -> list:
    """
    Apply AES MixColumns: each column is treated as a polynomial over GF(2^8)
    and multiplied by the fixed polynomial a(x) = 3x^3 + x^2 + x + 2.

    The operation for each column [s0, s1, s2, s3]:
      r0 = 2·s0 ⊕ 3·s1 ⊕   s2 ⊕   s3
      r1 =   s0 ⊕ 2·s1 ⊕ 3·s2 ⊕   s3
      r2 =   s0 ⊕   s1 ⊕ 2·s2 ⊕ 3·s3
      r3 = 3·s0 ⊕   s1 ⊕   s2 ⊕ 2·s3

    Parameters:
        state (list): 4×4 AES state matrix.

    Returns:
        list: New state after MixColumns.
    """
    result = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s = [state[r][c] for r in range(4)]
        result[0][c] = _gf_mul(2, s[0]) ^ _gf_mul(3, s[1]) ^ s[2] ^ s[3]
        result[1][c] = s[0] ^ _gf_mul(2, s[1]) ^ _gf_mul(3, s[2]) ^ s[3]
        result[2][c] = s[0] ^ s[1] ^ _gf_mul(2, s[2]) ^ _gf_mul(3, s[3])
        result[3][c] = _gf_mul(3, s[0]) ^ s[1] ^ s[2] ^ _gf_mul(2, s[3])
    return result


def inv_mix_columns(state: list) -> list:
    """
    Apply AES InvMixColumns: multiply each column by the inverse polynomial
    a^{-1}(x) = 11x^3 + 13x^2 + 9x + 14 (coefficients in GF(2^8)).

    For each column [s0, s1, s2, s3]:
      r0 = 14·s0 ⊕ 11·s1 ⊕ 13·s2 ⊕  9·s3
      r1 =  9·s0 ⊕ 14·s1 ⊕ 11·s2 ⊕ 13·s3
      r2 = 13·s0 ⊕  9·s1 ⊕ 14·s2 ⊕ 11·s3
      r3 = 11·s0 ⊕ 13·s1 ⊕  9·s2 ⊕ 14·s3

    Parameters:
        state (list): 4×4 AES state matrix.

    Returns:
        list: New state after InvMixColumns.
    """
    result = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s = [state[r][c] for r in range(4)]
        result[0][c] = (_gf_mul(14, s[0]) ^ _gf_mul(11, s[1]) ^
                        _gf_mul(13, s[2]) ^ _gf_mul(9, s[3]))
        result[1][c] = (_gf_mul(9, s[0]) ^ _gf_mul(14, s[1]) ^
                        _gf_mul(11, s[2]) ^ _gf_mul(13, s[3]))
        result[2][c] = (_gf_mul(13, s[0]) ^ _gf_mul(9, s[1]) ^
                        _gf_mul(14, s[2]) ^ _gf_mul(11, s[3]))
        result[3][c] = (_gf_mul(11, s[0]) ^ _gf_mul(13, s[1]) ^
                        _gf_mul(9, s[2]) ^ _gf_mul(14, s[3]))
    return result


def add_round_key(state: list, round_key: list) -> list:
    """
    XOR the AES state with a round key (AddRoundKey transformation).

    The round key is a flat 16-element list that is interpreted in column-major
    order to match the state layout.

    Parameters:
        state     (list): 4×4 AES state matrix.
        round_key (list): 16-element round key (flat list of ints).

    Returns:
        list: New state after XOR with round key.
    """
    result = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            result[r][c] = state[r][c] ^ round_key[r + 4 * c]
    return result


# ---------------------------------------------------------------------------
# Block-level encrypt / decrypt
# ---------------------------------------------------------------------------

def encrypt_block(plaintext: bytes, round_keys: list) -> bytes:
    """
    Encrypt a single 16-byte AES block using the standard (algebraic) S-Box.

    Performs the standard 10-round AES-128 encryption:
      Initial round key addition → 9 full rounds → final round (no MixColumns).

    Parameters:
        plaintext  (bytes): Exactly 16 bytes of plaintext.
        round_keys (list):  11 round keys from key_expansion().

    Returns:
        bytes: 16-byte ciphertext block.
    """
    state = bytes_to_state(plaintext)
    state = add_round_key(state, round_keys[0])

    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])

    # Final round: no MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return state_to_bytes(state)


def decrypt_block(ciphertext: bytes, round_keys: list) -> bytes:
    """
    Decrypt a single 16-byte AES block using the standard (algebraic) inverse S-Box.

    Applies inverse transformations in reverse round order:
      Initial key XOR → 9 full inverse rounds → final inverse round.

    Parameters:
        ciphertext (bytes): Exactly 16 bytes of ciphertext.
        round_keys (list):  11 round keys from key_expansion().

    Returns:
        bytes: 16-byte plaintext block.
    """
    state = bytes_to_state(ciphertext)
    state = add_round_key(state, round_keys[10])

    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)

    # Final inverse round: no InvMixColumns
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return state_to_bytes(state)


# ---------------------------------------------------------------------------
# High-level encrypt / decrypt (ECB mode with PKCS#7 padding)
# ---------------------------------------------------------------------------

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt arbitrary-length plaintext using AES-128-ECB with PKCS#7 padding.

    NOTE: ECB mode is used purely for benchmark convenience. In production systems,
    authenticated modes (e.g., AES-GCM) should be used instead.

    Parameters:
        plaintext (bytes): Data to encrypt (any length).
        key       (bytes): 16-byte AES key.

    Returns:
        bytes: Ciphertext (length is always a multiple of 16).
    """
    round_keys = key_expansion(key, _SBOX)
    padded = pkcs7_pad(plaintext)
    ciphertext = bytearray()
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        ciphertext.extend(encrypt_block(block, round_keys))
    return bytes(ciphertext)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-128-ECB ciphertext (produced by encrypt()) and strip PKCS#7 padding.

    Parameters:
        ciphertext (bytes): Encrypted data (must be a multiple of 16 bytes).
        key        (bytes): 16-byte AES key.

    Returns:
        bytes: Decrypted plaintext with padding removed.
    """
    round_keys = key_expansion(key, _SBOX)
    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        plaintext.extend(decrypt_block(block, round_keys))
    return pkcs7_unpad(bytes(plaintext))
