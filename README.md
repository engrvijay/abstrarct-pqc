# PQC Abstract Layer — liboqs Wrapper

A clean abstraction layer over [liboqs](https://github.com/open-quantum-safe/liboqs) in both **C** and **Python**.

---

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

```
┌──────────────────────────────────────────────┐
│              Your Application                │
├──────────────────────────────────────────────┤
│         pqc_abstract (C / Python)            │
│  ┌───────────────┐   ┌──────────────────┐   │
│  │  KEM API      │   │  SIG API         │   │
│  │  pqc_kem_new  │   │  pqc_sig_new     │   │
│  │  pqc_kem_keygen│  │  pqc_sig_keygen  │   │
│  │  pqc_kem_encaps│  │  pqc_sig_sign    │   │
│  │  pqc_kem_decaps│  │  pqc_sig_verify  │   │
│  └───────────────┘   └──────────────────┘   │
├──────────────────────────────────────────────┤
│            liboqs (C library)                │
│  OQS_KEM_new / OQS_SIG_new                  │
│  OQS_KEM_keypair / OQS_SIG_keypair           │
│  OQS_KEM_encaps  / OQS_SIG_sign             │
│  OQS_KEM_decaps  / OQS_SIG_verify           │
├──────────────────────────────────────────────┤
│    Algorithm implementations                 │
│  ML-KEM  ML-DSA  Falcon  BIKE  FrodoKEM  …  │
└──────────────────────────────────────────────┘
```

---

## C Layer

### Build

```bash
# Assumes liboqs installed under /usr/local
gcc -o pqc_example pqc_example.c pqc_abstract.c \
    -I/usr/local/include -L/usr/local/lib -loqs -lm

./pqc_example
```

### API Quick Reference

```c
pqc_init();                           // call once at startup
pqc_destroy();                        // call once at teardown

/* ── KEM ── */
PQC_KEM_Ctx   *ctx  = pqc_kem_new(PQC_KEM_ML_KEM_768);
PQC_KEM_Keys   keys = {0};
pqc_kem_keygen(ctx, &keys);

PQC_KEM_Encaps enc  = {0};
pqc_kem_encaps(ctx, keys.public_key, &enc);

uint8_t ss[32];  // allocate ctx->length_shared_secret bytes
pqc_kem_decaps(ctx, enc.ciphertext, keys.secret_key, ss);

pqc_kem_free_encaps(&enc);
pqc_kem_free_keys(&keys);
pqc_kem_free(ctx);

/* ── SIG ── */
PQC_SIG_Ctx  *sctx = pqc_sig_new(PQC_SIG_ML_DSA_65);
PQC_SIG_Keys  skeys = {0};
pqc_sig_keygen(sctx, &skeys);

PQC_Signature sig = {0};
pqc_sig_sign(sctx, msg, msg_len, skeys.secret_key, &sig);

PQC_STATUS v = pqc_sig_verify(sctx, msg, msg_len,
                               sig.data, sig.len,
                               skeys.public_key);

pqc_sig_free_signature(&sig);
pqc_sig_free_keys(&skeys);
pqc_sig_free(sctx);
```

### Status Codes

| Code | Meaning |
|---|---|
| `PQC_OK` | Success |
| `PQC_ERR_ALG_UNKNOWN` | Algorithm name not recognised |
| `PQC_ERR_ALG_DISABLED` | Disabled at liboqs compile time |
| `PQC_ERR_KEYGEN` | Key generation failed |
| `PQC_ERR_ENCAPS` | Encapsulation failed |
| `PQC_ERR_DECAPS` | Decapsulation failed |
| `PQC_ERR_SIGN` | Signing failed |
| `PQC_ERR_VERIFY` | Signature invalid |
| `PQC_ERR_ALLOC` | `malloc` returned NULL |

---

## Python Layer

### Install

```bash
pip install liboqs-python
python pqc_example.py
```

### API Quick Reference

```python
from pqc_abstract import KEM, SIG, KEMAlgorithm, SIGAlgorithm

# ── KEM ──
with KEM(KEMAlgorithm.ML_KEM_768) as kem:
    keys = kem.keygen()
    enc  = kem.encaps(keys.public_key)
    ss   = kem.decaps(enc.ciphertext, keys.secret_key)
    assert enc.shared_secret == ss

# ── SIG ──
with SIG(SIGAlgorithm.ML_DSA_65) as sig:
    keys      = sig.keygen()
    signature = sig.sign(b"message", keys.secret_key)
    valid     = sig.verify(b"message", signature, keys.public_key)

# context strings (ML-DSA)
sig = SIG("ML-DSA-65")
keys = sig.keygen()
s  = sig.sign(b"msg", keys.secret_key, ctx=b"app-ctx-v1")
ok = sig.verify(b"msg", s, keys.public_key, ctx=b"app-ctx-v1")
```

### Exceptions

| Exception | Raised when |
|---|---|
| `AlgorithmNotAvailable` | Unknown or disabled algorithm |
| `KeygenError` | Key generation failed |
| `EncapsulationError` | KEM encapsulation failed |
| `DecapsulationError` | KEM decapsulation failed |
| `SigningError` | Signing operation failed |
| `VerificationError` | Signature verification errored (not just invalid) |

---

## Recommended Algorithms (2024–2025)

| Use case | Algorithm | Standard |
|---|---|---|
| Key exchange (balanced) | ML-KEM-768 | NIST FIPS 203 |
| Key exchange (high security) | ML-KEM-1024 | NIST FIPS 203 |
| Signatures (balanced) | ML-DSA-65 | NIST FIPS 204 |
| Signatures (small keys) | Falcon-512 | NIST FIPS 206 |
| Signatures (conservative) | ML-DSA-87 | NIST FIPS 204 |
