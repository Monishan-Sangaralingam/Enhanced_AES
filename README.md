# Enhanced AES

Enhanced AES is a Python project that compares two AES-128 implementations:

- a standard version that computes the S-Box algebraically, and
- an enhanced version that uses a lookup-table (LUT) S-Box.

The project benchmarks both implementations on text and image data, checks that encryption and decryption round-trip correctly, measures the avalanche effect, and writes a formatted report to disk.

## What The Project Does

When you run the main script, it will:

1. Create the `sample_data/` and `results/` folders if they do not exist.
2. Generate a 10 KB sample text file and a 50 x 50 BMP image if they are missing.
3. Generate a random 16-byte AES-128 key.
4. Verify that both AES implementations can encrypt and decrypt the same plaintext correctly.
5. Benchmark encryption and decryption performance on the text and image data.
6. Run an avalanche-effect analysis with 1000 tests per implementation.
7. Save a formatted summary report to `enhanced_aes/results/report.txt`.

## Project Structure

```text
enhanced_aes/
	avalanche.py          Avalanche-effect analysis helpers
	benchmark.py          Timing and throughput benchmarking
	correct_sbox.txt      Reference S-Box values
	enhanced_aes.py       AES implementation using LUT S-Box
	main.py               Main entry point for the full workflow
	report.py             Generates results/report.txt
	sbox.py               S-Box construction helpers
	standard_aes.py       Baseline AES implementation
	utils.py              Shared AES utility functions
	verify_project.py     Manual verification script
	results/
		report.txt          Latest generated report
	sample_data/
		sample_text.txt     Generated sample text input
		sample_image.bmp    Generated sample image input
```

## Requirements

- Python 3.11 or newer
- No external packages are required; the project uses only the Python standard library

## Setup

If you want to keep the project isolated, activate the existing virtual environment from the project root:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
& ".venv/Scripts/Activate.ps1"
```

If you prefer not to activate the environment, you can run the project directly with the Python executable inside `.venv`.

## Run The Project

Run the main workflow from the project root:

```powershell
& ".venv/Scripts/python.exe" "enhanced_aes/main.py"
```

You can also run the file directly from inside the `enhanced_aes/` folder:

```powershell
& "../.venv/Scripts/python.exe" "main.py"
```

## Verify The Implementation

The repository includes a dedicated verification script that checks the S-Box, AES round-trip behavior, key expansion, and basic encryption/decryption expectations:

```powershell
& ".venv/Scripts/python.exe" "enhanced_aes/verify_project.py"
```

## Benchmark Output

The benchmark compares both AES versions on two datasets:

- `sample_text.txt` - a generated 10 KB ASCII text file
- `sample_image.bmp` - a generated 50 x 50 RGB BMP image

For each dataset, the project reports:

- average encryption time in milliseconds
- average decryption time in milliseconds
- encryption throughput in MB/s
- decryption throughput in MB/s

The benchmark table is printed to the console and also summarized in the generated report.

## Avalanche Analysis

The avalanche test flips bits across many trials and measures how strongly the ciphertext changes. The project prints a pass/fail result based on whether the measured bit-flip percentage stays within the 45% to 55% range, with 50% as the ideal target.

## Generated Files

After a run, these files are created or refreshed:

- `enhanced_aes/sample_data/sample_text.txt`
- `enhanced_aes/sample_data/sample_image.bmp`
- `enhanced_aes/results/report.txt`

The report includes:

- timestamp of the run
- benchmark timings and throughput
- avalanche results
- a short conclusion comparing the two implementations

## Notes

- The project uses ECB mode internally for benchmark convenience only. It is not recommended for real-world encryption.
- The enhanced implementation is designed to improve S-Box lookup performance, but the actual speed difference depends on the dataset and the Python runtime.
- The project verifies that both implementations produce the same ciphertext for the same plaintext and key.

## Troubleshooting

If Python cannot find a module, make sure you are running commands from the project root or using the virtual environment's Python executable.

If PowerShell blocks script activation, run the setup command shown above to allow activation in the current session only.

If you want to regenerate the sample data or report, simply delete the files in `sample_data/` or `results/` and run `main.py` again.
