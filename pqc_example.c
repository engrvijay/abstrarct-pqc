/**
 * @file pqc_example.c
 * @brief End-to-end usage example of the pqc_abstract layer.
 *
 * Demonstrates:
 *   1. KEM full round-trip  (keygen → encaps → decaps → compare shared secrets)
 *   2. SIG full round-trip  (keygen → sign → verify → tamper → detect)
 *   3. Context-string signing (ML-DSA)
 *
 * Build:
 *   gcc -o pqc_example pqc_example.c pqc_abstract.c \
 *       -I/usr/local/include -L/usr/local/lib -loqs -lm
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqc_abstract.h"

/* ── helpers ─────────────────────────────────────────────────────────────── */
static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("  %-22s [%4zu B] : ", label, len);
    size_t show = len > 16 ? 16 : len;
    for (size_t i = 0; i < show; i++) printf("%02x", buf[i]);
    if (len > 16) printf("…");
    printf("\n");
}

static void check(PQC_STATUS s, const char *op) {
    if (s != PQC_OK) {
        fprintf(stderr, "FAIL %-20s  %s\n", op, pqc_status_str(s));
        exit(EXIT_FAILURE);
    }
    printf("  %-35s  OK\n", op);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Demo 1 — KEM round-trip
 * ═══════════════════════════════════════════════════════════════════════════ */
static void demo_kem(const char *alg) {
    printf("\n╔══════════════════════════════════════════╗\n");
    printf("║  KEM demo : %-28s║\n", alg ? alg : PQC_KEM_DEFAULT);
    printf("╚══════════════════════════════════════════╝\n");

    /* 1. Create context */
    PQC_KEM_Ctx *ctx = pqc_kem_new(alg);
    if (!ctx) { fprintf(stderr, "Algorithm not available.\n"); return; }
    pqc_kem_print_info(ctx);
    printf("\n");

    /* 2. Key generation */
    PQC_KEM_Keys keys = {0};
    check(pqc_kem_keygen(ctx, &keys), "keygen");
    print_hex("public_key",   keys.public_key, keys.pk_len);
    print_hex("secret_key",   keys.secret_key, keys.sk_len);

    /* 3. Encapsulation (sender uses public key) */
    PQC_KEM_Encaps enc = {0};
    check(pqc_kem_encaps(ctx, keys.public_key, &enc), "encaps");
    print_hex("ciphertext",   enc.ciphertext,    enc.ct_len);
    print_hex("shared_secret(enc)", enc.shared_secret, enc.ss_len);

    /* 4. Decapsulation (receiver uses secret key) */
    uint8_t *ss_dec = malloc(ctx->length_shared_secret);
    if (!ss_dec) { fprintf(stderr, "malloc failed\n"); exit(1); }
    check(pqc_kem_decaps(ctx, enc.ciphertext, keys.secret_key, ss_dec), "decaps");
    print_hex("shared_secret(dec)", ss_dec, ctx->length_shared_secret);

    /* 5. Compare shared secrets */
    if (memcmp(enc.shared_secret, ss_dec, ctx->length_shared_secret) == 0)
        printf("  %-35s  MATCH ✓\n", "shared-secret comparison");
    else
        printf("  %-35s  MISMATCH ✗\n", "shared-secret comparison");

    /* Cleanup */
    free(ss_dec);
    pqc_kem_free_encaps(&enc);
    pqc_kem_free_keys(&keys);
    pqc_kem_free(ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Demo 2 — SIG round-trip
 * ═══════════════════════════════════════════════════════════════════════════ */
static void demo_sig(const char *alg) {
    printf("\n╔══════════════════════════════════════════╗\n");
    printf("║  SIG demo : %-28s║\n", alg ? alg : PQC_SIG_DEFAULT);
    printf("╚══════════════════════════════════════════╝\n");

    PQC_SIG_Ctx *ctx = pqc_sig_new(alg);
    if (!ctx) { fprintf(stderr, "Algorithm not available.\n"); return; }
    pqc_sig_print_info(ctx);
    printf("\n");

    /* 1. Key generation */
    PQC_SIG_Keys keys = {0};
    check(pqc_sig_keygen(ctx, &keys), "keygen");
    print_hex("public_key", keys.public_key, keys.pk_len);
    print_hex("secret_key", keys.secret_key, keys.sk_len);

    /* 2. Sign a message */
    const uint8_t msg[]  = "Hello, post-quantum world!";
    size_t        msg_len = sizeof(msg) - 1;
    PQC_Signature sig = {0};
    check(pqc_sig_sign(ctx, msg, msg_len, keys.secret_key, &sig), "sign");
    print_hex("signature", sig.data, sig.len);
    printf("  %-35s  %zu B\n", "actual signature length", sig.len);

    /* 3. Verify — should succeed */
    PQC_STATUS v = pqc_sig_verify(ctx, msg, msg_len, sig.data, sig.len, keys.public_key);
    printf("  %-35s  %s\n", "verify (valid)", (v == PQC_OK) ? "PASS ✓" : "FAIL ✗");

    /* 4. Tamper with message — should fail */
    uint8_t bad_msg[] = "Hello, post-quantum w0rld!";
    v = pqc_sig_verify(ctx, bad_msg, msg_len, sig.data, sig.len, keys.public_key);
    printf("  %-35s  %s\n", "verify (tampered msg)",
           (v == PQC_ERR_VERIFY) ? "REJECTED ✓" : "BUG — accepted ✗");

    /* 5. Context-string signing (if supported) */
    if (ctx->ctx_support) {
        PQC_Signature sig_ctx = {0};
        const uint8_t app_ctx[] = "my-app-v1";
        check(pqc_sig_sign_ctx(ctx, msg, msg_len,
                                app_ctx, sizeof(app_ctx)-1,
                                keys.secret_key, &sig_ctx),
              "sign_with_ctx");
        v = pqc_sig_verify(ctx, msg, msg_len,
                           sig_ctx.data, sig_ctx.len,
                           keys.public_key);
        /* verify_with_ctx_str is needed for ctx signatures; plain verify should fail */
        printf("  %-35s  %s\n", "plain verify of ctx-sig (expected fail)",
               (v != PQC_OK) ? "REJECTED ✓" : "BUG — accepted ✗");
        pqc_sig_free_signature(&sig_ctx);
    }

    /* Cleanup */
    pqc_sig_free_signature(&sig);
    pqc_sig_free_keys(&keys);
    pqc_sig_free(ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════════════ */
int main(void) {
    pqc_init();

    printf("liboqs version : %s\n", OQS_version());

    /* — KEM demos — */
    demo_kem(PQC_KEM_ML_KEM_768);    /* NIST FIPS 203 standard */
    demo_kem(PQC_KEM_KYBER_512);     /* Pre-standardisation variant */

    /* — SIG demos — */
    demo_sig(PQC_SIG_ML_DSA_65);     /* NIST FIPS 204 standard */
    demo_sig(PQC_SIG_FALCON_512);    /* Fast lattice-based alternative */

    /* — Algorithm listing — */
    printf("\n");
    pqc_kem_list_algorithms();
    printf("\n");
    pqc_sig_list_algorithms();

    pqc_destroy();
    return 0;
}
