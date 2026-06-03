"""
avalanche.py — Avalanche Effect Analysis

Measures how well each AES implementation satisfies the Strict Avalanche Criterion:
flipping a single input bit should cause approximately 50% of the output bits to flip.

Ideal AES avalanche: ~50% (≈64 of 128 ciphertext bits change per input-bit flip).
Pass range used here: [45%, 55%] — a commonly accepted threshold for block ciphers.
"""

import os
import random
from typing import Callable


def avalanche_effect(
    encrypt_fn: Callable[[bytes, bytes], bytes],
    key: bytes,
    num_tests: int = 1000,
) -> float:
    """
    Estimate the avalanche effect percentage for the given encryption function.

    Algorithm (per test iteration):
      1. Generate a random 16-byte plaintext P.
      2. Encrypt P → ciphertext A.
      3. Flip exactly one random bit in P to get P'.
      4. Encrypt P' → ciphertext B.
      5. XOR A and B; count set bits (differing bits).
      6. Express as a percentage of total ciphertext bits (128).

    The final result is the average over all num_tests iterations.

    Parameters:
        encrypt_fn (Callable): encrypt(plaintext: bytes, key: bytes) -> bytes.
        key        (bytes):    16-byte AES key shared across all tests.
        num_tests  (int):      Number of random plaintexts to test (default: 1000).

    Returns:
        float: Average percentage of bits that differ in ciphertext A vs B
               when one plaintext bit is flipped (ideally ~50.0).
    """
    total_bit_diff_pct = 0.0
    total_bits = 128  # 16-byte ciphertext × 8 bits

    for _ in range(num_tests):
        # Step 1: random 16-byte plaintext
        plaintext = os.urandom(16)

        # Step 2: encrypt original plaintext
        ct_a = encrypt_fn(plaintext, key)

        # Step 3: flip one random bit
        bit_pos = random.randint(0, 127)          # bit index within 16 bytes
        byte_idx = bit_pos // 8
        bit_idx = bit_pos % 8
        modified = bytearray(plaintext)
        modified[byte_idx] ^= (1 << bit_idx)     # toggle the selected bit

        # Step 4: encrypt modified plaintext
        ct_b = encrypt_fn(bytes(modified), key)

        # Step 5: count differing bits via XOR
        diff_bits = 0
        for ba, bb in zip(ct_a, ct_b):
            diff_bits += bin(ba ^ bb).count('1')

        # Step 6: percentage of bits that changed
        total_bit_diff_pct += (diff_bits / total_bits) * 100.0

    return total_bit_diff_pct / num_tests


def analyze_avalanche(
    standard_enc: Callable[[bytes, bytes], bytes],
    enhanced_enc: Callable[[bytes, bytes], bytes],
    key: bytes,
    num_tests: int = 1000,
) -> dict:
    """
    Run the avalanche effect test on both AES implementations and compare results.

    Pass criterion: the average bit-flip percentage must fall within [45%, 55%].
    This range is a standard indicator of strong diffusion in block ciphers.

    Parameters:
        standard_enc (Callable): Standard AES encrypt function.
        enhanced_enc (Callable): Enhanced AES encrypt function.
        key          (bytes):    16-byte AES key.
        num_tests    (int):      Number of test iterations per implementation.

    Returns:
        dict: {
            'standard_pct'  : float — average bit-flip % for standard AES,
            'enhanced_pct'  : float — average bit-flip % for enhanced AES,
            'standard_pass' : bool  — True if standard_pct ∈ [45%, 55%],
            'enhanced_pass' : bool  — True if enhanced_pct ∈ [45%, 55%],
        }
    """
    pass_low, pass_high = 45.0, 55.0

    print(f"[Avalanche] Running {num_tests} tests on Standard AES ...")
    std_pct = avalanche_effect(standard_enc, key, num_tests)

    print(f"[Avalanche] Running {num_tests} tests on Enhanced AES ...")
    enh_pct = avalanche_effect(enhanced_enc, key, num_tests)

    std_pass = pass_low <= std_pct <= pass_high
    enh_pass = pass_low <= enh_pct <= pass_high
    verdict = "PASS" if (std_pass and enh_pass) else "FAIL"

    return {
        # Primary keys (used by report.py)
        "standard_pct":  round(std_pct, 4),
        "enhanced_pct":  round(enh_pct, 4),
        "standard_pass": std_pass,
        "enhanced_pass": enh_pass,
        # Alias keys (used by verify_project.py)
        "standard": round(std_pct, 4),
        "enhanced": round(enh_pct, 4),
        "verdict":  verdict,
    }
