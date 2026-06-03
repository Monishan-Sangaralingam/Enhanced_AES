"""
utils.py — AES Utility Functions

Provides shared helper routines used by both standard_aes.py and enhanced_aes.py:
  - AES-128 key schedule (key_expansion)
  - PKCS#7 padding and de-padding
  - Hex formatting for display
  - State ↔ bytes conversion helpers
"""

from typing import List


# ---------------------------------------------------------------------------
# AES Round Constants (RCON) for key schedule
# ---------------------------------------------------------------------------
# RCON[i] = x^(i-1) in GF(2^8), used during key expansion.
# Values are stored as the four-byte word [RC(i), 0x00, 0x00, 0x00].
RCON = [
    0x00,  # unused (index 0)
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
]


def key_expansion(key: bytes, sbox: list) -> List[List[int]]:
    """
    Perform the AES-128 key schedule to derive 11 round keys from a 128-bit key.

    AES-128 uses 10 rounds, so 11 round keys (including the initial key) are required.
    The expansion follows the FIPS 197 specification:
      - The first 4 words are the original key.
      - Each subsequent word W[i] = W[i-4] XOR g(W[i-1]) if i % 4 == 0,
        or W[i] = W[i-4] XOR W[i-1] otherwise.
      - g(w) = SubWord(RotWord(w)) XOR RCON[i/4].

    Parameters:
        key  (bytes): 16-byte (128-bit) AES key.
        sbox (list):  256-element S-Box to use for SubWord during expansion.

    Returns:
        List[List[int]]: 11 round keys, each as a flat list of 16 ints (bytes).
    """
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}.")

    # Work with a list of 4-byte words; 44 words total for AES-128.
    words = []
    for i in range(4):
        words.append(list(key[i * 4:(i + 1) * 4]))

    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            # RotWord: rotate left by one byte
            temp = temp[1:] + temp[:1]
            # SubWord: apply S-Box to each byte
            temp = [sbox[b] for b in temp]
            # XOR with round constant
            temp[0] ^= RCON[i // 4]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])

    # Group 4 words into each round key (16 bytes each)
    round_keys = []
    for r in range(11):
        rk = []
        for w in range(4):
            rk.extend(words[r * 4 + w])
        round_keys.append(rk)
    return round_keys


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to 'data' so its length is a multiple of block_size.

    The padding byte value equals the number of padding bytes added (1–16).
    If data is already a multiple of block_size, a full extra block of padding
    is appended (per PKCS#7 specification) to ensure unambiguous removal.

    Parameters:
        data       (bytes): Raw plaintext bytes.
        block_size (int):   AES block size, default 16.

    Returns:
        bytes: Padded data whose length is a multiple of block_size.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from 'data'.

    Validates that the padding bytes are consistent before stripping them.

    Parameters:
        data (bytes): Padded plaintext bytes.

    Returns:
        bytes: Original data with padding removed.

    Raises:
        ValueError: If padding is invalid.
    """
    if not data:
        raise ValueError("Cannot unpad empty data.")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Invalid padding byte: {pad_len:#04x}.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding bytes are inconsistent.")
    return data[:-pad_len]


def bytes_to_state(block: bytes) -> List[List[int]]:
    """
    Convert a 16-byte AES block into a 4×4 state matrix (column-major order).

    AES operates on a 4×4 matrix of bytes where the mapping is:
        state[row][col] = block[row + 4*col]

    Parameters:
        block (bytes): Exactly 16 bytes.

    Returns:
        List[List[int]]: 4×4 list of ints representing the AES state.
    """
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(state: List[List[int]]) -> bytes:
    """
    Flatten a 4×4 AES state matrix back into a 16-byte sequence (column-major).

    Parameters:
        state (List[List[int]]): 4×4 AES state.

    Returns:
        bytes: 16-byte block.
    """
    return bytes(state[r][c] for c in range(4) for r in range(4))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two equal-length byte sequences element-wise.

    Parameters:
        a (bytes): First byte sequence.
        b (bytes): Second byte sequence (same length as a).

    Returns:
        bytes: Element-wise XOR result.
    """
    return bytes(x ^ y for x, y in zip(a, b))


def format_hex(data: bytes, width: int = 32) -> str:
    """
    Format a byte sequence as an uppercase hexadecimal string with optional line wrapping.

    Parameters:
        data  (bytes): Bytes to format.
        width (int):   Number of hex characters per line (default 32 = 16 bytes).

    Returns:
        str: Formatted hex string.
    """
    hex_str = data.hex().upper()
    lines = [hex_str[i:i + width] for i in range(0, len(hex_str), width)]
    return "\n".join(lines)
