# Enhanced AES

This project compares a standard AES implementation with an enhanced AES variant that uses a lookup-table S-box for faster encryption.

## Contents

- `enhanced_aes/main.py` runs the benchmark, avalanche test, and report generation.
- `enhanced_aes/standard_aes.py` contains the baseline AES implementation.
- `enhanced_aes/enhanced_aes.py` contains the optimized AES implementation.
- `enhanced_aes/results/report.txt` stores the latest generated project report.

## Run

```powershell
& "D:/6thSemester/Information Security/IS Project/.venv/Scripts/python.exe" "D:/6thSemester/Information Security/IS Project/enhanced_aes/main.py"
```
