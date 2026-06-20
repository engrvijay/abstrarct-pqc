#!/usr/bin/env python3
"""
pqc_example.py — End-to-end usage demo of pqc_abstract.py
==========================================================
Demonstrates:
  1. KEM full round-trip  (keygen → encaps → decaps → compare)
  2. SIG full round-trip  (keygen → sign → verify → tamper detection)
  3. Context-string signing
  4. Algorithm listing & introspection
  5. Context-manager (with) usage pattern

Run:
    pip install liboqs-python
    python pqc_example.py
"""

import sys
from pqc_abstract import (
    KEM, SIG,
    KEMAlgorithm, SIGAlgorithm,
    PQCError, VerificationError,
    list_kem_algorithms, list_sig_algorithms,
    kem_info, sig_info,
)


def banner(title: str) -> None:
    print(f"\n{'═'*55}")
    print(f"  {title}")
    print('═'*55)


def hex_preview(data: bytes, n: int = 16) -> str:
    return data[:n].hex() + ("…" if len(data) > n else "")


# ─────────────────────────────────────────────────────────────
# Demo 1 — KEM round-trip
# ─────────────────────────────────────────────────────────────

def demo_kem(alg: str) -> None:
    banner(f"KEM  ·  {alg}")

    kem = KEM(alg)
    print(kem.info)
    print()

    # 1. Key generation
    keys = kem.keygen()
    print(f"  Public key : {hex_preview(keys.public_key)}  [{len(keys.public_key)} B]")
    print(f"  Secret key : <{len(keys.secret_key)} B hidden>")

    # 2. Encapsulation (sender side)
    enc = kem.encaps(keys.public_key)
    print(f"  Ciphertext : {hex_preview(enc.ciphertext)}  [{len(enc.ciphertext)} B]")
    print(f"  SS (enc)   : {hex_preview(enc.shared_secret)}  [{len(enc.shared_secret)} B]")

    # 3. Decapsulation (receiver side)
    ss_dec = kem.decaps(enc.ciphertext, keys.secret_key)
    print(f"  SS (dec)   : {hex_preview(ss_dec)}")

    # 4. Compare
    match = enc.shared_secret == ss_dec
    print(f"  Match      : {'✓  PASS' if match else '✗  FAIL'}")
    assert match, "Shared secrets do not match — BUG!"

    # Wipe sensitive material
    keys.wipe()
    enc.wipe()


# ─────────────────────────────────────────────────────────────
# Demo 2 — SIG round-trip
# ─────────────────────────────────────────────────────────────

def demo_sig(alg: str) -> None:
    banner(f"SIG  ·  {alg}")

    sig = SIG(alg)
    print(sig.info)
    print()

    # 1. Key generation
    keys = sig.keygen()
    print(f"  Public key : {hex_preview(keys.public_key)}  [{len(keys.public_key)} B]")

    # 2. Sign
    message = b"Hello, post-quantum world!"
    signature = sig.sign(message, keys.secret_key)
    print(f"  Signature  : {hex_preview(signature)}  [{len(signature)} B]")

    # 3. Verify — should pass
    ok = sig.verify(message, signature, keys.public_key)
    print(f"  Verify OK  : {'✓  PASS' if ok else '✗  FAIL'}")
    assert ok

    # 4. Tamper with message — should fail
    tampered = b"Hello, post-quantum w0rld!"
    ok_bad = sig.verify(tampered, signature, keys.public_key)
    print(f"  Tampered   : {'✓  REJECTED (expected)' if not ok_bad else '✗  ACCEPTED (BUG)'}")
    assert not ok_bad

    # 5. Context-string signing (ML-DSA supports it)
    if sig.info.ctx_str_support:
        ctx_str = b"my-application-v1"
        sig_ctx = sig.sign(message, keys.secret_key, ctx=ctx_str)
        ok_ctx  = sig.verify(message, sig_ctx, keys.public_key, ctx=ctx_str)
        print(f"  Ctx-sign   : {'✓  PASS' if ok_ctx else '✗  FAIL'}")
        assert ok_ctx

        # Wrong context string must fail
        ok_wrong_ctx = sig.verify(message, sig_ctx, keys.public_key, ctx=b"wrong-ctx")
        print(f"  Wrong ctx  : {'✓  REJECTED' if not ok_wrong_ctx else '✗  ACCEPTED (BUG)'}")

    keys.wipe()


# ─────────────────────────────────────────────────────────────
# Demo 3 — Context-manager pattern
# ─────────────────────────────────────────────────────────────

def demo_context_manager() -> None:
    banner("Context-manager usage")

    with KEM(KEMAlgorithm.ML_KEM_512) as kem:
        keys = kem.keygen()
        enc  = kem.encaps(keys.public_key)
        ss   = kem.decaps(enc.ciphertext, keys.secret_key)
        print(f"  KEM ({kem.algorithm}) shared secret : {hex_preview(ss)}")
        assert enc.shared_secret == ss

    with SIG(SIGAlgorithm.ML_DSA_44) as sig:
        keys = sig.keygen()
        s    = sig.sign(b"context manager demo", keys.secret_key)
        ok   = sig.verify(b"context manager demo", s, keys.public_key)
        print(f"  SIG ({sig.algorithm}) verify : {'✓' if ok else '✗'}")
        assert ok


# ─────────────────────────────────────────────────────────────
# Demo 4 — Algorithm listing & introspection
# ─────────────────────────────────────────────────────────────

def demo_listing() -> None:
    banner("Algorithm listing")

    kem_algs = list_kem_algorithms()
    sig_algs = list_sig_algorithms()

    print(f"  Enabled KEM algorithms ({len(kem_algs)}):")
    for name in kem_algs[:8]:
        print(f"    • {name}")
    if len(kem_algs) > 8:
        print(f"    … and {len(kem_algs)-8} more")

    print(f"\n  Enabled SIG algorithms ({len(sig_algs)}):")
    for name in sig_algs[:8]:
        print(f"    • {name}")
    if len(sig_algs) > 8:
        print(f"    … and {len(sig_algs)-8} more")

    print(f"\n  Quick info — {KEMAlgorithm.DEFAULT}:")
    info = kem_info(KEMAlgorithm.DEFAULT)
    print(f"    PK={info.public_key_length}B  "
          f"SK={info.secret_key_length}B  "
          f"CT={info.ciphertext_length}B  "
          f"SS={info.shared_secret_length}B")


# ─────────────────────────────────────────────────────────────
# Demo 5 — Error handling
# ─────────────────────────────────────────────────────────────

def demo_errors() -> None:
    banner("Error handling")

    # Unknown algorithm
    try:
        KEM("NotARealKEM")
    except PQCError as e:
        print(f"  Unknown KEM : caught PQCError → {e}")

    # Bad signature
    sig  = SIG()
    keys = sig.keygen()
    s    = sig.sign(b"real message", keys.secret_key)
    ok   = sig.verify(b"different message", s, keys.public_key)
    print(f"  Bad verify  : {'correctly returned False' if not ok else 'BUG'}")


# ─────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────

def main() -> int:
    try:
        # KEM demos
        demo_kem(KEMAlgorithm.ML_KEM_768)
        demo_kem(KEMAlgorithm.KYBER_512)

        # SIG demos
        demo_sig(SIGAlgorithm.ML_DSA_65)
        demo_sig(SIGAlgorithm.FALCON_512)

        # Extras
        demo_context_manager()
        demo_listing()
        demo_errors()

        print("\n✓  All demos completed successfully.\n")
        return 0

    except PQCError as exc:
        print(f"\n✗  PQC error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"\n✗  Unexpected error: {exc}", file=sys.stderr)
        raise


if __name__ == "__main__":
    sys.exit(main())
