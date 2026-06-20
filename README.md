# abstrarct-pqc - PQC Abstract Layer


## Files

| File | Purpose |
|---|---|
| `pqc_abstract.h` | C public API header |
| `pqc_abstract.c` | C implementation |
| `pqc_example.c` | C end-to-end demo |
| `pqc_abstract.py` | Python wrapper (uses `oqs` package) |
| `pqc_example.py` | Python end-to-end demo |

---

## Architecture
┌──────────────────────────────────────────────┐
│              Your Application                │
├──────────────────────────────────────────────┤
│         pqc_abstract (C / Python)            │
├──────────────────────────────────────────────┤
│    Algorithm implementations                 │
│  ML-KEM  ML-DSA  Falcon  BIKE  FrodoKEM  …   │
└──────────────────────────────────────────────┘



### Status Codes

| Code | Meaning |
|---|---|
| `PQC_OK`               | Success |
| `PQC_ERR_ALG_UNKNOWN`  | Algorithm name not recognised |
| `PQC_ERR_ALG_DISABLED` | Disabled at liboqs compile time |
| `PQC_ERR_KEYGEN`       | Key generation failed |
| `PQC_ERR_ENCAPS`       | Encapsulation failed |
| `PQC_ERR_DECAPS`       | Decapsulation failed |
| `PQC_ERR_SIGN`         | Signing failed |
| `PQC_ERR_VERIFY`       | Signature invalid |
| `PQC_ERR_ALLOC`        | `malloc` returned NULL |
---

## C Layer

### Build

```bash
# Assumes liboqs installed under /usr/local
gcc -o pqc_example pqc_example.c pqc_abstract.c \
    -I/usr/local/include -L/usr/local/lib -loqs -lm

## Python Layer

### Install

```bash
pip install liboqs-python
python pqc_example.py
```

## Recommended Algorithms (2024–2025)
| Use case                    | Algorithm   | Standard      |
| Key exchange (balanced)     | ML-KEM-768  | NIST FIPS 203 |
| Key exchange (high security)| ML-KEM-1024 | NIST FIPS 203 |
| Signatures (balanced)       | ML-DSA-65   | NIST FIPS 204 |
| Signatures (small keys)     | Falcon-512  | NIST FIPS 206 |
| Signatures (conservative)   | ML-DSA-87   | NIST FIPS 204 |
