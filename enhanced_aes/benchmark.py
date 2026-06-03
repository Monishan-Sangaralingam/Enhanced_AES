"""
benchmark.py — AES Performance Benchmarking

Provides functions to measure encryption/decryption throughput for any
AES implementation that exposes the same (plaintext, key) → ciphertext interface.

Metrics reported:
  - Average encryption and decryption time in milliseconds.
  - Throughput in MB/s for both directions.

All timing uses time.perf_counter() for the highest available resolution.
"""

import time
from typing import Callable


def run_benchmark(
    encrypt_fn: Callable[[bytes, bytes], bytes],
    decrypt_fn: Callable[[bytes, bytes], bytes],
    data: bytes,
    key: bytes,
    label: str,
    iterations: int = 100,
) -> dict:
    """
    Benchmark an AES encrypt/decrypt pair over a fixed dataset.

    The function runs 'iterations' full encrypt passes on 'data', then
    'iterations' full decrypt passes on the resulting ciphertext, and
    measures wall-clock time using time.perf_counter().

    Throughput formula:
        throughput (MB/s) = (len(data) * iterations) / total_time_seconds / 1_000_000

    Parameters:
        encrypt_fn  (Callable): encrypt(plaintext: bytes, key: bytes) -> bytes.
        decrypt_fn  (Callable): decrypt(ciphertext: bytes, key: bytes) -> bytes.
        data        (bytes):    Input data to encrypt (arbitrary length).
        key         (bytes):    16-byte AES key.
        label       (str):      Human-readable name for this benchmark run.
        iterations  (int):      Number of repetitions (default: 100).

    Returns:
        dict: {
            'label'               : str   — benchmark label,
            'avg_enc_time_ms'     : float — average encryption time in ms,
            'avg_dec_time_ms'     : float — average decryption time in ms,
            'enc_throughput_MBps' : float — encryption throughput in MB/s,
            'dec_throughput_MBps' : float — decryption throughput in MB/s,
        }
    """
    data_size = len(data)

    # ---- Encryption benchmark ----
    ciphertext = encrypt_fn(data, key)   # one warm-up / result capture
    enc_start = time.perf_counter()
    for _ in range(iterations):
        encrypt_fn(data, key)
    enc_end = time.perf_counter()
    total_enc_time = enc_end - enc_start
    avg_enc_ms = (total_enc_time / iterations) * 1000
    enc_throughput = (data_size * iterations) / total_enc_time / 1e6

    # ---- Decryption benchmark ----
    dec_start = time.perf_counter()
    for _ in range(iterations):
        decrypt_fn(ciphertext, key)
    dec_end = time.perf_counter()
    total_dec_time = dec_end - dec_start
    avg_dec_ms = (total_dec_time / iterations) * 1000
    dec_throughput = (data_size * iterations) / total_dec_time / 1e6

    return {
        "label": label,
        "avg_enc_time_ms": round(avg_enc_ms, 4),
        "avg_dec_time_ms": round(avg_dec_ms, 4),
        "enc_throughput_MBps": round(enc_throughput, 6),
        "dec_throughput_MBps": round(dec_throughput, 6),
    }


def compare_benchmarks(results_list: list) -> None:
    """
    Print a formatted comparison table of multiple benchmark results to stdout.

    Each row of the table corresponds to one benchmark result dict returned
    by run_benchmark(), and columns show label, average times, and throughput.

    Parameters:
        results_list (list): List of dicts as returned by run_benchmark().

    Returns:
        None
    """
    header = (
        f"{'Label':<40} {'Enc Time(ms)':>14} {'Dec Time(ms)':>14} "
        f"{'Enc MB/s':>12} {'Dec MB/s':>12}"
    )
    separator = "-" * len(header)

    print("\n" + "=" * len(header))
    print("  BENCHMARK RESULTS")
    print("=" * len(header))
    print(header)
    print(separator)

    for r in results_list:
        print(
            f"{r['label']:<40} "
            f"{r['avg_enc_time_ms']:>14.4f} "
            f"{r['avg_dec_time_ms']:>14.4f} "
            f"{r['enc_throughput_MBps']:>12.6f} "
            f"{r['dec_throughput_MBps']:>12.6f}"
        )

    print("=" * len(header) + "\n")
