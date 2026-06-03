"""
verify_project.py — Enhanced AES Project Verification Script

Runs manual, section-by-section checks across every module in the project.
Prints clear PASS/FAIL for each condition; never raises or silently swallows
a failure. Produces a final summary of total passed/failed checks.

Usage:
    python verify_project.py
"""

import sys
import os
import random
import traceback
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure imports resolve from the project root regardless of working directory
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Global counters (mutated inside check()) — using a list for closure access
# ---------------------------------------------------------------------------
_counts = {"passed": 0, "failed": 0}


def check(label: str, condition: bool, expected=None, actual=None) -> None:
    """
    Evaluate a single boolean condition and print PASS or FAIL.

    Parameters:
        label     (str):  Human-readable description of what is being checked.
        condition (bool): True = PASS, False = FAIL.
        expected  (any):  Optional expected value to display on failure.
        actual    (any):  Optional actual value to display on failure.

    Returns:
        None
    """
    if condition:
        _counts["passed"] += 1
        print(f"  [PASS] {label}")
    else:
        _counts["failed"] += 1
        print(f"  [FAIL] {label}")
        if expected is not None:
            print(f"         Expected : {expected}")
        if actual is not None:
            print(f"         Got      : {actual}")


# ---------------------------------------------------------------------------
# Script header
# ---------------------------------------------------------------------------
print("=" * 60)
print(" Enhanced AES Project — Verification Script")
print("=" * 60)
print(f" Running from : {os.getcwd()}")
print(f" Python       : {sys.version}")
print("=" * 60)


# ===========================================================================
# SECTION 1: S-Box Verification
# ===========================================================================
print("\n========================================")
print(" SECTION 1: S-Box Verification")
print("========================================")

_sbox_module_ok = False
try:
    from sbox import build_sbox_algebraic, build_sbox_lut, build_inv_sbox
    _sbox_module_ok = True
    print("  [INFO] sbox.py imported successfully.")
except Exception as exc:
    print(f"  [ERROR] Failed to import sbox.py: {exc}")
    print("  Skipping Section 1 — cannot continue without S-Box.")

if _sbox_module_ok:
    try:
        # Step 1.2 — Build both S-Boxes
        algebraic_sbox = build_sbox_algebraic()
        lut_sbox       = build_sbox_lut()

        # Step 1.3 — Basic structural checks
        check("algebraic_sbox has exactly 256 values",
              len(algebraic_sbox) == 256,
              expected=256, actual=len(algebraic_sbox))

        check("lut_sbox has exactly 256 values",
              len(lut_sbox) == 256,
              expected=256, actual=len(lut_sbox))

        check("All algebraic_sbox values are in range [0, 255]",
              all(0 <= v <= 255 for v in algebraic_sbox))

        check("All lut_sbox values are in range [0, 255]",
              all(0 <= v <= 255 for v in lut_sbox))

        check("algebraic_sbox is a bijection (256 unique values)",
              len(set(algebraic_sbox)) == 256,
              expected=256, actual=len(set(algebraic_sbox)))

        check("lut_sbox is a bijection (256 unique values)",
              len(set(lut_sbox)) == 256,
              expected=256, actual=len(set(lut_sbox)))

        # Step 1.4 — Algebraic == LUT byte-for-byte
        mismatches = [(i, algebraic_sbox[i], lut_sbox[i])
                      for i in range(256) if algebraic_sbox[i] != lut_sbox[i]]
        if not mismatches:
            check("Algebraic S-Box matches LUT S-Box exactly", True)
        else:
            check("Algebraic S-Box matches LUT S-Box exactly", False,
                  expected="No mismatches",
                  actual=f"{len(mismatches)} mismatches")
            print("         First 5 mismatches (index: algebraic vs lut):")
            for idx, a, b in mismatches[:5]:
                print(f"           [{idx:#04x}] algebraic=0x{a:02X}  lut=0x{b:02X}")

        # Step 1.5 — Known AES S-Box spot checks (FIPS 197 values)
        known = {
            0x00: 0x63,
            0x01: 0x7C,
            0x53: 0xED,
            0xFF: 0x16,
            0x80: 0xCD,
        }
        for inp, expected_out in known.items():
            check(f"lut_sbox[0x{inp:02X}] == 0x{expected_out:02X}",
                  lut_sbox[inp] == expected_out,
                  expected=hex(expected_out), actual=hex(lut_sbox[inp]))

        # Step 1.6 — Inverse S-Box round-trip: inv_sbox[sbox[x]] == x for all x
        inv_sbox = build_inv_sbox(lut_sbox)
        first_inv_fail = None
        for x in range(256):
            if inv_sbox[lut_sbox[x]] != x:
                first_inv_fail = (x, lut_sbox[x], inv_sbox[lut_sbox[x]])
                break
        check("inv_sbox[sbox[x]] == x for all x in 0..255",
              first_inv_fail is None,
              expected="Round-trip identity",
              actual=None if first_inv_fail is None else
              f"inv_sbox[sbox[{first_inv_fail[0]}]] = {first_inv_fail[2]}, expected {first_inv_fail[0]}")

    except Exception as exc:
        print(f"  [ERROR] Unexpected exception in Section 1:\n  {traceback.format_exc()}")
        _counts["failed"] += 1


# ===========================================================================
# SECTION 2: Standard AES — Encrypt / Decrypt
# ===========================================================================
print("\n========================================")
print(" SECTION 2: Standard AES — Encrypt / Decrypt")
print("========================================")

_std_module_ok = False
_std_aes = None
try:
    import standard_aes as _std_aes
    _std_module_ok = True
    print("  [INFO] standard_aes.py imported successfully.")
except Exception as exc:
    print(f"  [ERROR] Failed to import standard_aes.py: {exc}")
    print("  Skipping Section 2.")

if _std_module_ok:
    try:
        from sbox import build_sbox_algebraic as _alg_sbox
        from utils import key_expansion as _key_exp

        # Step 2.2 — Key expansion
        key_seq = bytes(range(16))
        round_keys = _key_exp(key_seq, _alg_sbox())
        check("[Standard AES] key_expansion returns 11 round keys",
              len(round_keys) == 11,
              expected=11, actual=len(round_keys))
        check("[Standard AES] Each round key is 16 bytes",
              all(len(rk) == 16 for rk in round_keys),
              expected="All 16 bytes", actual=[len(rk) for rk in round_keys if len(rk) != 16])

        # Step 2.3 — Single block encrypt / decrypt round-trip
        plaintext_block = bytes(range(16))
        ciphertext_block = _std_aes.encrypt_block(plaintext_block, round_keys)
        recovered_block  = _std_aes.decrypt_block(ciphertext_block, round_keys)

        check("[Standard AES] Encryption changes the data",
              ciphertext_block != plaintext_block)
        check("[Standard AES] Decryption recovers original plaintext",
              recovered_block == plaintext_block,
              expected=plaintext_block.hex().upper(),
              actual=recovered_block.hex().upper())
        print(f"  Ciphertext (hex): {ciphertext_block.hex().upper()}")

        # Step 2.4 — Full encrypt/decrypt with PKCS#7 for three lengths
        for pt_len in (7, 16, 37):
            key_rand = os.urandom(16)
            plaintext = os.urandom(pt_len)
            ct = _std_aes.encrypt(plaintext, key_rand)
            pt = _std_aes.decrypt(ct, key_rand)
            check(f"[Standard AES] len={pt_len}: ciphertext length is multiple of 16",
                  len(ct) % 16 == 0,
                  expected="multiple of 16", actual=len(ct))
            check(f"[Standard AES] len={pt_len}: decrypt(encrypt(pt)) == pt",
                  pt == plaintext)
            print(f"  Plaintext length: {pt_len} bytes  →  Ciphertext length: {len(ct)} bytes")

        # Step 2.5 — Different keys produce different ciphertext
        plaintext_fixed = b"Hello AES World!"
        key1 = os.urandom(16)
        key2 = os.urandom(16)
        ct1 = _std_aes.encrypt(plaintext_fixed, key1)
        ct2 = _std_aes.encrypt(plaintext_fixed, key2)
        check("[Standard AES] Different keys produce different ciphertext",
              ct1 != ct2)

        # Step 2.6 — Changing plaintext changes ciphertext
        key_c = os.urandom(16)
        ct_a = _std_aes.encrypt(b"AAAAAAAAAAAAAAAA", key_c)
        ct_b = _std_aes.encrypt(b"AAAAAAAAAAAAAAAB", key_c)
        check("[Standard AES] Changing plaintext changes ciphertext",
              ct_a != ct_b)

    except Exception as exc:
        print(f"  [ERROR] Unexpected exception in Section 2:\n  {traceback.format_exc()}")
        _counts["failed"] += 1


# ===========================================================================
# SECTION 3: Enhanced AES — Encrypt / Decrypt
# ===========================================================================
print("\n========================================")
print(" SECTION 3: Enhanced AES — Encrypt / Decrypt")
print("========================================")

_enh_module_ok = False
_enh_aes = None
try:
    import enhanced_aes as _enh_aes
    _enh_module_ok = True
    print("  [INFO] enhanced_aes.py imported successfully.")
except Exception as exc:
    print(f"  [ERROR] Failed to import enhanced_aes.py: {exc}")
    print("  Skipping Section 3.")

if _enh_module_ok:
    try:
        from sbox import build_sbox_lut as _lut_sbox
        from utils import key_expansion as _key_exp2

        # Step 3.2 — Key expansion (LUT S-Box)
        key_seq = bytes(range(16))
        round_keys_e = _key_exp2(key_seq, _lut_sbox())
        check("[Enhanced AES] key_expansion returns 11 round keys",
              len(round_keys_e) == 11,
              expected=11, actual=len(round_keys_e))
        check("[Enhanced AES] Each round key is 16 bytes",
              all(len(rk) == 16 for rk in round_keys_e),
              expected="All 16 bytes", actual=[len(rk) for rk in round_keys_e if len(rk) != 16])

        # Step 3.3 — Single block encrypt/decrypt round-trip
        plaintext_block_e = bytes(range(16))
        ciphertext_block_e = _enh_aes.encrypt_block(plaintext_block_e, round_keys_e)
        recovered_block_e  = _enh_aes.decrypt_block(ciphertext_block_e, round_keys_e)
        check("[Enhanced AES] Encryption changes the data",
              ciphertext_block_e != plaintext_block_e)
        check("[Enhanced AES] Decryption recovers original plaintext",
              recovered_block_e == plaintext_block_e,
              expected=plaintext_block_e.hex().upper(),
              actual=recovered_block_e.hex().upper())
        print(f"  Ciphertext (hex): {ciphertext_block_e.hex().upper()}")

        # Step 3.4 — Full encrypt/decrypt for three lengths
        for pt_len in (7, 16, 37):
            key_rand = os.urandom(16)
            plaintext = os.urandom(pt_len)
            ct = _enh_aes.encrypt(plaintext, key_rand)
            pt = _enh_aes.decrypt(ct, key_rand)
            check(f"[Enhanced AES] len={pt_len}: ciphertext length is multiple of 16",
                  len(ct) % 16 == 0,
                  expected="multiple of 16", actual=len(ct))
            check(f"[Enhanced AES] len={pt_len}: decrypt(encrypt(pt)) == pt",
                  pt == plaintext)
            print(f"  Plaintext length: {pt_len} bytes  →  Ciphertext length: {len(ct)} bytes")

        # Step 3.5 — Different keys produce different ciphertext
        plaintext_fixed_e = b"Hello AES World!"
        key1_e = os.urandom(16)
        key2_e = os.urandom(16)
        ct1_e = _enh_aes.encrypt(plaintext_fixed_e, key1_e)
        ct2_e = _enh_aes.encrypt(plaintext_fixed_e, key2_e)
        check("[Enhanced AES] Different keys produce different ciphertext",
              ct1_e != ct2_e)

        # Step 3.6 — Changing plaintext changes ciphertext
        key_c_e = os.urandom(16)
        ct_a_e = _enh_aes.encrypt(b"AAAAAAAAAAAAAAAA", key_c_e)
        ct_b_e = _enh_aes.encrypt(b"AAAAAAAAAAAAAAAB", key_c_e)
        check("[Enhanced AES] Changing plaintext changes ciphertext",
              ct_a_e != ct_b_e)

    except Exception as exc:
        print(f"  [ERROR] Unexpected exception in Section 3:\n  {traceback.format_exc()}")
        _counts["failed"] += 1


# ===========================================================================
# SECTION 4: Cross-Compatibility Check
# ===========================================================================
print("\n========================================")
print(" SECTION 4: Cross-Compatibility Check")
print("========================================")

try:
    if not (_std_module_ok and _enh_module_ok):
        print("  [SKIP] Both standard_aes and enhanced_aes must be importable.")
    else:
        # Step 4.2 — 10 random round-trips
        cross_pairs = []   # (key, plaintext, std_ct, enh_ct)
        for i in range(10):
            key_x   = os.urandom(16)
            plain_x = os.urandom(random.randint(1, 200))
            std_ct  = _std_aes.encrypt(plain_x, key_x)
            enh_ct  = _enh_aes.encrypt(plain_x, key_x)
            check(f"Round {i+1}: Standard and Enhanced produce identical ciphertext",
                  std_ct == enh_ct,
                  expected="equal ciphertext",
                  actual=f"std={std_ct[:8].hex()}... enh={enh_ct[:8].hex()}...")
            cross_pairs.append((key_x, plain_x, std_ct, enh_ct))

        # Step 4.3 — Cross-decrypt check
        for i, (key_x, plain_x, std_ct, enh_ct) in enumerate(cross_pairs):
            pt_from_std = _std_aes.decrypt(enh_ct, key_x)
            pt_from_enh = _enh_aes.decrypt(std_ct, key_x)
            check(f"Cross-decrypt {i+1}: standard_aes.decrypt(enh_ciphertext) == plaintext",
                  pt_from_std == plain_x)
            check(f"Cross-decrypt {i+1}: enhanced_aes.decrypt(std_ciphertext) == plaintext",
                  pt_from_enh == plain_x)

        # Step 4.4 — Design note
        print()
        print("  NOTE: The only difference between Standard and Enhanced AES is the")
        print("   S-Box construction method. Since both S-Boxes are mathematically")
        print("   identical, all outputs must match.")

except Exception as exc:
    print(f"  [ERROR] Unexpected exception in Section 4:\n  {traceback.format_exc()}")
    _counts["failed"] += 1


# ===========================================================================
# SECTION 5: Performance Benchmark
# ===========================================================================
print("\n========================================")
print(" SECTION 5: Performance Benchmark")
print("========================================")

_bench_module_ok = False
_std_result = None
_enh_result = None
try:
    from benchmark import run_benchmark, compare_benchmarks
    _bench_module_ok = True
    print("  [INFO] benchmark.py imported successfully.")
except Exception as exc:
    print(f"  [ERROR] Failed to import benchmark.py: {exc}")
    print("  Skipping Section 5.")

if _bench_module_ok and _std_module_ok and _enh_module_ok:
    try:
        # Step 5.2 — 50 KB test payload
        data = os.urandom(50 * 1024)
        key_b = os.urandom(16)
        print("  [INFO] Running benchmarks (50 iterations × 50 KB) — please wait ...")

        # Step 5.3 — Standard AES benchmark
        _std_result = run_benchmark(
            _std_aes.encrypt, _std_aes.decrypt,
            data, key_b,
            label="Standard AES",
            iterations=50,
        )

        # Step 5.4 — Enhanced AES benchmark
        _enh_result = run_benchmark(
            _enh_aes.encrypt, _enh_aes.decrypt,
            data, key_b,
            label="Enhanced AES",
            iterations=50,
        )

        # Step 5.5 — Side-by-side comparison table
        s = _std_result
        e = _enh_result
        col_w = 16
        sep = f"  +{'─'*22}+{'─'*col_w}+{'─'*col_w}+"
        print()
        print(sep)
        print(f"  | {'Metric':<20} | {'Standard AES':>{col_w-2}} | {'Enhanced AES':>{col_w-2}} |")
        print(sep)
        print(f"  | {'Avg Encrypt Time':<20} | {s['avg_enc_time_ms']:>{col_w-5}.3f} ms | {e['avg_enc_time_ms']:>{col_w-5}.3f} ms |")
        print(f"  | {'Avg Decrypt Time':<20} | {s['avg_dec_time_ms']:>{col_w-5}.3f} ms | {e['avg_dec_time_ms']:>{col_w-5}.3f} ms |")
        print(f"  | {'Encrypt Throughput':<20} | {s['enc_throughput_MBps']:>{col_w-6}.4f} MB/s | {e['enc_throughput_MBps']:>{col_w-6}.4f} MB/s |")
        print(f"  | {'Decrypt Throughput':<20} | {s['dec_throughput_MBps']:>{col_w-6}.4f} MB/s | {e['dec_throughput_MBps']:>{col_w-6}.4f} MB/s |")
        print(sep)
        print()

        # Step 5.6 — Sanity checks
        check("Standard AES avg_enc_time_ms > 0",
              _std_result["avg_enc_time_ms"] > 0)
        check("Enhanced AES avg_enc_time_ms > 0",
              _enh_result["avg_enc_time_ms"] > 0)
        check("Standard AES enc_throughput_MBps > 0",
              _std_result["enc_throughput_MBps"] > 0)
        check("Enhanced AES enc_throughput_MBps > 0",
              _enh_result["enc_throughput_MBps"] > 0)

        # Step 5.7 — Speedup comparison
        speedup = _std_result["avg_enc_time_ms"] / _enh_result["avg_enc_time_ms"]
        if speedup > 1.0:
            print(f"  Enhanced AES is {speedup:.2f}x FASTER than Standard AES (encryption)")
        elif speedup < 1.0:
            print(f"  Standard AES is {1/speedup:.2f}x faster (LUT slower in this run — Python overhead)")
        else:
            print("  Both implementations performed equally")

    except Exception as exc:
        print(f"  [ERROR] Unexpected exception in Section 5:\n  {traceback.format_exc()}")
        _counts["failed"] += 1
elif _bench_module_ok:
    print("  [SKIP] Standard/Enhanced AES imports failed — cannot benchmark.")


# ===========================================================================
# SECTION 6: Avalanche Effect Analysis
# ===========================================================================
print("\n========================================")
print(" SECTION 6: Avalanche Effect Analysis")
print("========================================")

_av_module_ok = False
_av_results   = None
try:
    from avalanche import analyze_avalanche
    _av_module_ok = True
    print("  [INFO] avalanche.py imported successfully.")
except Exception as exc:
    print(f"  [ERROR] Failed to import avalanche.py: {exc}")
    print("  Skipping Section 6.")

if _av_module_ok and _std_module_ok and _enh_module_ok:
    try:
        key_av = os.urandom(16)
        print("  [INFO] Running 1000 avalanche tests per implementation — please wait ...")
        _av_results = analyze_avalanche(
            _std_aes.encrypt,
            _enh_aes.encrypt,
            key_av,
            num_tests=1000,
        )

        # Step 6.3 — Print results
        print(f"  Standard AES Avalanche : {_av_results['standard']:.2f}%")
        print(f"  Enhanced AES Avalanche : {_av_results['enhanced']:.2f}%")
        print(f"  Ideal target           : ~50.00%")

        # Step 6.4 — Range checks
        check("Standard AES avalanche within acceptable range (45–55%)",
              45.0 <= _av_results["standard"] <= 55.0,
              expected="[45%, 55%]", actual=f"{_av_results['standard']:.2f}%")
        check("Enhanced AES avalanche within acceptable range (45–55%)",
              45.0 <= _av_results["enhanced"] <= 55.0,
              expected="[45%, 55%]", actual=f"{_av_results['enhanced']:.2f}%")

        # Step 6.5 — Overall verdict
        check("Avalanche Effect security verdict == PASS",
              _av_results["verdict"] == "PASS",
              expected="PASS", actual=_av_results["verdict"])

        # Step 6.6 — Both scores are close to each other
        diff = abs(_av_results["standard"] - _av_results["enhanced"])
        check(f"Both implementations have similar avalanche scores (diff: {diff:.2f}%)",
              diff < 5.0,
              expected="< 5.0%", actual=f"{diff:.2f}%")

    except Exception as exc:
        print(f"  [ERROR] Unexpected exception in Section 6:\n  {traceback.format_exc()}")
        _counts["failed"] += 1
elif _av_module_ok:
    print("  [SKIP] AES imports failed — cannot run avalanche analysis.")


# ===========================================================================
# SECTION 7: File I/O and Report Generation
# ===========================================================================
print("\n========================================")
print(" SECTION 7: File I/O and Report Generation")
print("========================================")

_report_module_ok = False
try:
    import report as report_mod
    _report_module_ok = True
    print("  [INFO] report.py imported successfully.")
except Exception as exc:
    print(f"  [ERROR] Failed to import report.py: {exc}")
    print("  Skipping Section 7.")

if _report_module_ok:
    try:
        # Use benchmark and avalanche results collected earlier, or create stubs
        bench_for_report = []
        if _std_result and _enh_result:
            bench_for_report = [_std_result, _enh_result]
        else:
            # Minimal stub so generate_report doesn't crash
            stub = {"label": "Stub", "avg_enc_time_ms": 0.0,
                    "avg_dec_time_ms": 0.0, "enc_throughput_MBps": 0.0,
                    "dec_throughput_MBps": 0.0}
            bench_for_report = [stub]

        av_for_report = _av_results if _av_results else {
            "standard_pct": 0.0, "enhanced_pct": 0.0,
            "standard_pass": False, "enhanced_pass": False,
            "standard": 0.0, "enhanced": 0.0, "verdict": "FAIL",
        }

        # Step 7.2 — Generate report
        report_mod.generate_report(bench_for_report, av_for_report)

        # Step 7.3 — File exists
        report_path = Path("results/report.txt")
        check("Report file created at results/report.txt",
              report_path.exists())

        # Step 7.4 — Not empty
        if report_path.exists():
            content = report_path.read_text(encoding="utf-8")
            check("Report file contains meaningful content (> 100 chars)",
                  len(content) > 100,
                  expected="> 100 chars", actual=f"{len(content)} chars")

            # Step 7.5 — Key sections present
            for keyword in ("Standard AES", "Enhanced AES", "Avalanche", "Throughput"):
                check(f'Report contains "{keyword}"',
                      keyword in content)

    except Exception as exc:
        print(f"  [ERROR] Unexpected exception in Section 7:\n  {traceback.format_exc()}")
        _counts["failed"] += 1


# ===========================================================================
# SECTION 8: Sample Data Files
# ===========================================================================
print("\n========================================")
print(" SECTION 8: Sample Data Files")
print("========================================")

try:
    txt_path = Path("sample_data/sample_text.txt")
    bmp_path = Path("sample_data/sample_image.bmp")

    # If files are missing, attempt to generate them now (re-use main.py helpers)
    if not txt_path.exists() or not bmp_path.exists():
        print("  [INFO] Sample files missing — generating now ...")
        try:
            import main as _main_mod
            _main_mod.generate_sample_text(txt_path)
            _main_mod.generate_sample_bmp(bmp_path)
        except Exception as gen_exc:
            print(f"  [WARN] Could not auto-generate sample files: {gen_exc}")

    # Step 8.1 — Existence checks
    check("sample_data/sample_text.txt exists",
          txt_path.exists())
    check("sample_data/sample_image.bmp exists",
          bmp_path.exists())

    # Step 8.2 — Size checks
    if txt_path.exists():
        txt_size = txt_path.stat().st_size
        check(f"sample_text.txt is at least 1 KB (actual: {txt_size} bytes)",
              txt_size >= 1024,
              expected=">= 1024", actual=txt_size)

    if bmp_path.exists():
        bmp_size = bmp_path.stat().st_size
        check(f"sample_image.bmp is non-empty (actual: {bmp_size} bytes)",
              bmp_size > 0,
              expected="> 0", actual=bmp_size)

    # Step 8.3 — Encrypt and decrypt the text file content
    if txt_path.exists() and _std_module_ok:
        key_tf = os.urandom(16)
        txt_data = txt_path.read_bytes()
        ct_tf = _std_aes.encrypt(txt_data, key_tf)
        pt_tf = _std_aes.decrypt(ct_tf, key_tf)
        check("Text file encrypts and decrypts correctly (standard_aes)",
              pt_tf == txt_data)

except Exception as exc:
    print(f"  [ERROR] Unexpected exception in Section 8:\n  {traceback.format_exc()}")
    _counts["failed"] += 1


# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
total   = _counts["passed"] + _counts["failed"]
passed  = _counts["passed"]
failed  = _counts["failed"]

print("\n========================================")
print(" VERIFICATION COMPLETE")
print("========================================")
print(f" Total checks : {total}")
print(f" Passed       : {passed}")
print(f" Failed       : {failed}")
print(" ----------------------------------------")
if failed == 0:
    print(" Overall result: ALL CHECKS PASSED ✓")
else:
    print(f" Overall result: {failed} CHECK(S) FAILED — review output above")
print("========================================\n")

sys.exit(0 if failed == 0 else 1)
