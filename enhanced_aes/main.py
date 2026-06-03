"""
main.py — Enhanced AES: Optimized S-Box for Faster Encryption
           Entry Point

Orchestrates the full project pipeline:
  1. Generates sample data files (10KB text, 50×50 BMP image) if missing.
  2. Generates a random 16-byte AES key.
  3. Benchmarks Standard AES (algebraic S-Box) and Enhanced AES (LUT S-Box)
     on both the text and image datasets.
  4. Prints a benchmark comparison table.
  5. Runs an Avalanche Effect analysis for both implementations.
  6. Saves a formatted text report to results/report.txt.
"""

import os
import sys
import struct
from pathlib import Path

# Ensure imports work when run from inside the enhanced_aes/ directory
# or from its parent directory.
sys.path.insert(0, str(Path(__file__).parent))

import standard_aes
import enhanced_aes
from benchmark import run_benchmark, compare_benchmarks
from avalanche import analyze_avalanche
import report as report_module


# ---------------------------------------------------------------------------
# Sample data generation helpers
# ---------------------------------------------------------------------------

def generate_sample_text(path: Path, target_size: int = 10 * 1024) -> None:
    """
    Generate a ~10KB plain-text file of repeating ASCII lorem ipsum content.

    Parameters:
        path        (Path): Destination file path.
        target_size (int):  Minimum number of bytes to write (default: 10240).

    Returns:
        None
    """
    lorem = (
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
        "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris "
        "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
        "reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla "
        "pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
        "culpa qui officia deserunt mollit anim id est laborum. "
    )
    # Repeat until we reach the target size
    content = (lorem * ((target_size // len(lorem)) + 2))[:target_size]
    path.write_text(content, encoding="ascii")
    print(f"[Setup] Generated sample text file: {path} ({len(content)} bytes)")


def generate_sample_bmp(path: Path, width: int = 50, height: int = 50) -> None:
    """
    Generate a minimal 50×50 RGB BMP image filled with a gradient pattern.

    The BMP is written entirely in raw bytes using struct without any external
    image library — standard Python only.

    Parameters:
        path   (Path): Destination file path.
        width  (int):  Image width in pixels (default: 50).
        height (int):  Image height in pixels (default: 50).

    Returns:
        None
    """
    # BMP stores rows bottom-to-top; row stride must be a multiple of 4 bytes.
    row_size = width * 3                          # 3 bytes per pixel (BGR)
    padding = (4 - row_size % 4) % 4             # pad each row to 4-byte boundary
    padded_row_size = row_size + padding
    pixel_array_size = padded_row_size * height
    file_size = 54 + pixel_array_size             # 54-byte header + pixel data

    # ------ BMP File Header (14 bytes) ------
    bmp_file_header = struct.pack(
        "<2sIHHI",
        b"BM",           # Magic number
        file_size,       # File size in bytes
        0,               # Reserved 1
        0,               # Reserved 2
        54,              # Offset to pixel data
    )

    # ------ DIB Header — BITMAPINFOHEADER (40 bytes) ------
    dib_header = struct.pack(
        "<IiiHHIIiiII",
        40,              # Header size
        width,           # Image width
        height,          # Image height (positive = bottom-up)
        1,               # Colour planes
        24,              # Bits per pixel (24-bit RGB)
        0,               # Compression (0 = none)
        pixel_array_size,
        2835,            # X pixels per metre (~72 DPI)
        2835,            # Y pixels per metre
        0,               # Colours in table (0 = default)
        0,               # Important colours (0 = all)
    )

    # ------ Pixel Data: simple colour gradient ------
    pixel_rows = []
    for row in range(height):
        row_bytes = bytearray()
        for col in range(width):
            # BGR colour gradient based on position
            b = int((row / height) * 255)
            g = int((col / width) * 255)
            r = int(((row + col) / (height + width)) * 255)
            row_bytes += bytes([b, g, r])
        row_bytes += b"\x00" * padding  # row padding
        pixel_rows.append(bytes(row_bytes))

    # BMP rows are stored bottom-to-top
    pixel_data = b"".join(reversed(pixel_rows))

    with open(path, "wb") as f:
        f.write(bmp_file_header + dib_header + pixel_data)

    print(f"[Setup] Generated sample BMP file:  {path} ({file_size} bytes)")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Run the full Enhanced AES benchmark and analysis pipeline.

    Steps:
      1. Create required directories (sample_data/, results/).
      2. Generate sample data files if they do not already exist.
      3. Read sample files as bytes.
      4. Generate a random 16-byte AES key.
      5–8. Benchmark Standard and Enhanced AES on both files.
      9.  Print a comparison table.
      10. Run Avalanche Effect analysis.
      11. Print avalanche results.
      12. Generate and save the results report.
      13. Print project completion message.

    Returns:
        None
    """
    print("\n" + "=" * 60)
    print("  ENHANCED AES: OPTIMIZED S-BOX FOR FASTER ENCRYPTION")
    print("=" * 60 + "\n")

    # ----------------------------------------------------------------
    # Step 1: Ensure required directories exist
    # ----------------------------------------------------------------
    base_dir = Path(__file__).parent
    sample_dir = base_dir / "sample_data"
    results_dir = base_dir / "results"
    sample_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)
    print("[Setup] Directories ready: sample_data/, results/")

    # ----------------------------------------------------------------
    # Step 2: Generate sample files if needed
    # ----------------------------------------------------------------
    text_path = sample_dir / "sample_text.txt"
    bmp_path = sample_dir / "sample_image.bmp"

    if not text_path.exists():
        generate_sample_text(text_path, target_size=10 * 1024)
    else:
        print(f"[Setup] Using existing text file: {text_path}")

    if not bmp_path.exists():
        generate_sample_bmp(bmp_path, width=50, height=50)
    else:
        print(f"[Setup] Using existing BMP file:  {bmp_path}")

    # ----------------------------------------------------------------
    # Step 3: Read sample data
    # ----------------------------------------------------------------
    text_data = text_path.read_bytes()
    image_data = bmp_path.read_bytes()
    print(f"\n[Data] Text file : {len(text_data):,} bytes")
    print(f"[Data] Image file: {len(image_data):,} bytes")

    # ----------------------------------------------------------------
    # Step 4: Generate a random 128-bit AES key (never hardcoded)
    # ----------------------------------------------------------------
    key = os.urandom(16)
    print(f"\n[Key] Random AES-128 key: {key.hex().upper()}")

    # ----------------------------------------------------------------
    # Quick correctness sanity-check before benchmarking
    # ----------------------------------------------------------------
    print("\n[Sanity Check] Verifying encrypt/decrypt round-trip ...")
    test_plain = b"Hello AES World!"
    std_ct = standard_aes.encrypt(test_plain, key)
    std_pt = standard_aes.decrypt(std_ct, key)
    enh_ct = enhanced_aes.encrypt(test_plain, key)
    enh_pt = enhanced_aes.decrypt(enh_ct, key)
    assert std_pt == test_plain, "Standard AES round-trip FAILED"
    assert enh_pt == test_plain, "Enhanced AES round-trip FAILED"
    assert std_ct == enh_ct, "Standard and Enhanced AES produce different ciphertext!"
    print("[Sanity Check] PASSED — both implementations produce identical ciphertext.")

    # ----------------------------------------------------------------
    # Steps 5–8: Benchmarks
    # ----------------------------------------------------------------
    ITERATIONS = 50   # Reduce to 50 for reasonable wall-clock time in pure Python
    print(f"\n[Benchmark] Running {ITERATIONS} iterations per implementation per dataset...")
    print("  (This may take a minute — pure-Python AES is intentionally not optimised.)\n")

    # Step 5: Standard AES on text
    res_std_text = run_benchmark(
        standard_aes.encrypt, standard_aes.decrypt,
        text_data, key,
        label="Standard AES (algebraic) — Text",
        iterations=ITERATIONS,
    )
    print(f"  [Done] {res_std_text['label']}")

    # Step 6: Enhanced AES on text
    res_enh_text = run_benchmark(
        enhanced_aes.encrypt, enhanced_aes.decrypt,
        text_data, key,
        label="Enhanced AES (LUT)       — Text",
        iterations=ITERATIONS,
    )
    print(f"  [Done] {res_enh_text['label']}")

    # Step 7: Standard AES on image
    res_std_img = run_benchmark(
        standard_aes.encrypt, standard_aes.decrypt,
        image_data, key,
        label="Standard AES (algebraic) — Image",
        iterations=ITERATIONS,
    )
    print(f"  [Done] {res_std_img['label']}")

    # Step 8: Enhanced AES on image
    res_enh_img = run_benchmark(
        enhanced_aes.encrypt, enhanced_aes.decrypt,
        image_data, key,
        label="Enhanced AES (LUT)       — Image",
        iterations=ITERATIONS,
    )
    print(f"  [Done] {res_enh_img['label']}")

    # ----------------------------------------------------------------
    # Step 9: Comparison table
    # ----------------------------------------------------------------
    all_results = [res_std_text, res_enh_text, res_std_img, res_enh_img]
    compare_benchmarks(all_results)

    # ----------------------------------------------------------------
    # Step 10: Avalanche Effect analysis
    # ----------------------------------------------------------------
    print("[Avalanche] Analyzing avalanche effect (1000 tests each) ...")
    avalanche_results = analyze_avalanche(
        standard_aes.encrypt,
        enhanced_aes.encrypt,
        key,
        num_tests=1000,
    )

    # ----------------------------------------------------------------
    # Step 11: Print avalanche results
    # ----------------------------------------------------------------
    print("\n" + "=" * 60)
    print("  AVALANCHE EFFECT RESULTS")
    print("=" * 60)
    std_pass = "PASS ✓" if avalanche_results["standard_pass"] else "FAIL ✗"
    enh_pass = "PASS ✓" if avalanche_results["enhanced_pass"] else "FAIL ✗"
    print(f"  Standard AES (algebraic S-Box) : {avalanche_results['standard_pct']:.4f}%  [{std_pass}]")
    print(f"  Enhanced AES (LUT S-Box)       : {avalanche_results['enhanced_pct']:.4f}%  [{enh_pass}]")
    print(f"  Pass criterion: bit-flip percentage within [45%, 55%] (ideal ≈ 50%)")
    print("=" * 60 + "\n")

    # ----------------------------------------------------------------
    # Step 12: Generate report
    # ----------------------------------------------------------------
    os.chdir(base_dir)   # Ensure report.py resolves "results/" relative to project root
    report_module.generate_report(all_results, avalanche_results)

    # ----------------------------------------------------------------
    # Step 13: Done
    # ----------------------------------------------------------------
    print("\nProject complete. See results/ folder for output.")


if __name__ == "__main__":
    main()
