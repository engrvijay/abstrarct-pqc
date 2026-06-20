/**
 * @file pqc_abstract.c
 * @brief Implementation of the Post-Quantum Cryptography Abstract Layer.
 *
 * SPDX-License-Identifier: MIT
 */

#include "pqc_abstract.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── liboqs public headers ─────────────────────────────────────────────────── */
#include <oqs/oqs.h>
#include <oqs/kem.h>
#include <oqs/sig.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Zeroise and free a heap buffer. */
static void _secure_free(uint8_t **buf, size_t len) {
    if (buf && *buf) {
        OQS_MEM_cleanse(*buf, len);
        OQS_MEM_secure_free(*buf, len);
        *buf = NULL;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Library lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

void pqc_init(void) {
    OQS_init();
}

void pqc_destroy(void) {
    OQS_destroy();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Status helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

const char *pqc_status_str(PQC_STATUS s) {
    switch (s) {
        case PQC_OK:              return "OK";
        case PQC_ERR_GENERIC:     return "Generic error";
        case PQC_ERR_NULL:        return "NULL argument or uninitialised context";
        case PQC_ERR_ALG_UNKNOWN: return "Unknown algorithm name";
        case PQC_ERR_ALG_DISABLED:return "Algorithm disabled at compile time";
        case PQC_ERR_KEYGEN:      return "Key-generation failure";
        case PQC_ERR_ENCAPS:      return "Encapsulation failure";
        case PQC_ERR_DECAPS:      return "Decapsulation failure";
        case PQC_ERR_SIGN:        return "Signing failure";
        case PQC_ERR_VERIFY:      return "Signature verification failed";
        case PQC_ERR_ALLOC:       return "Memory allocation failure";
        default:                   return "Unknown status code";
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * KEM — context management
 * ═══════════════════════════════════════════════════════════════════════════ */

PQC_KEM_Ctx *pqc_kem_new(const char *alg) {
    const char *name = alg ? alg : PQC_KEM_DEFAULT;

    OQS_KEM *kem = OQS_KEM_new(name);
    if (!kem) {
        /* Distinguish unknown vs disabled */
        fprintf(stderr, "[pqc] KEM '%s': not available (unknown or disabled at build time)\n", name);
        return NULL;
    }

    PQC_KEM_Ctx *ctx = (PQC_KEM_Ctx *)calloc(1, sizeof(PQC_KEM_Ctx));
    if (!ctx) {
        OQS_KEM_free(kem);
        return NULL;
    }

    ctx->_kem                  = kem;
    ctx->algorithm             = kem->method_name;
    ctx->length_public_key     = kem->length_public_key;
    ctx->length_secret_key     = kem->length_secret_key;
    ctx->length_ciphertext     = kem->length_ciphertext;
    ctx->length_shared_secret  = kem->length_shared_secret;
    ctx->nist_level            = (uint8_t)kem->claimed_nist_level;
    ctx->ind_cca               = kem->ind_cca;
    return ctx;
}

void pqc_kem_free(PQC_KEM_Ctx *ctx) {
    if (!ctx) return;
    OQS_KEM_free(ctx->_kem);
    ctx->_kem = NULL;
    free(ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * KEM — key-pair operations
 * ═══════════════════════════════════════════════════════════════════════════ */

PQC_STATUS pqc_kem_keygen(const PQC_KEM_Ctx *ctx, PQC_KEM_Keys *keys) {
    if (!ctx || !ctx->_kem || !keys) return PQC_ERR_NULL;

    memset(keys, 0, sizeof(*keys));

    keys->pk_len = ctx->length_public_key;
    keys->sk_len = ctx->length_secret_key;

    keys->public_key = (uint8_t *)malloc(keys->pk_len);
    keys->secret_key = (uint8_t *)malloc(keys->sk_len);
    if (!keys->public_key || !keys->secret_key) {
        pqc_kem_free_keys(keys);
        return PQC_ERR_ALLOC;
    }

    OQS_STATUS rc = OQS_KEM_keypair(ctx->_kem, keys->public_key, keys->secret_key);
    if (rc != OQS_SUCCESS) {
        pqc_kem_free_keys(keys);
        return PQC_ERR_KEYGEN;
    }
    return PQC_OK;
}

void pqc_kem_free_keys(PQC_KEM_Keys *keys) {
    if (!keys) return;
    _secure_free(&keys->public_key, keys->pk_len);
    _secure_free(&keys->secret_key, keys->sk_len);
    keys->pk_len = keys->sk_len = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * KEM — encapsulation / decapsulation
 * ═══════════════════════════════════════════════════════════════════════════ */

PQC_STATUS pqc_kem_encaps(const PQC_KEM_Ctx *ctx,
                           const uint8_t     *pk,
                           PQC_KEM_Encaps    *result) {
    if (!ctx || !ctx->_kem || !pk || !result) return PQC_ERR_NULL;

    memset(result, 0, sizeof(*result));
    result->ct_len = ctx->length_ciphertext;
    result->ss_len = ctx->length_shared_secret;

    result->ciphertext    = (uint8_t *)malloc(result->ct_len);
    result->shared_secret = (uint8_t *)malloc(result->ss_len);
    if (!result->ciphertext || !result->shared_secret) {
        pqc_kem_free_encaps(result);
        return PQC_ERR_ALLOC;
    }

    OQS_STATUS rc = OQS_KEM_encaps(ctx->_kem,
                                    result->ciphertext,
                                    result->shared_secret,
                                    pk);
    if (rc != OQS_SUCCESS) {
        pqc_kem_free_encaps(result);
        return PQC_ERR_ENCAPS;
    }
    return PQC_OK;
}

PQC_STATUS pqc_kem_decaps(const PQC_KEM_Ctx *ctx,
                           const uint8_t     *ciphertext,
                           const uint8_t     *sk,
                           uint8_t           *shared_secret) {
    if (!ctx || !ctx->_kem || !ciphertext || !sk || !shared_secret)
        return PQC_ERR_NULL;

    OQS_STATUS rc = OQS_KEM_decaps(ctx->_kem, shared_secret, ciphertext, sk);
    return (rc == OQS_SUCCESS) ? PQC_OK : PQC_ERR_DECAPS;
}

void pqc_kem_free_encaps(PQC_KEM_Encaps *e) {
    if (!e) return;
    _secure_free(&e->ciphertext,    e->ct_len);
    _secure_free(&e->shared_secret, e->ss_len);
    e->ct_len = e->ss_len = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * KEM — introspection utilities
 * ═══════════════════════════════════════════════════════════════════════════ */

void pqc_kem_list_algorithms(void) {
    printf("Available KEM algorithms:\n");
    for (size_t i = 0; i < OQS_KEM_algs_length; i++) {
        const char *name = OQS_KEM_alg_identifier(i);
        if (OQS_KEM_alg_is_enabled(name))
            printf("  [enabled]  %s\n", name);
        else
            printf("  [disabled] %s\n", name);
    }
}

void pqc_kem_print_info(const PQC_KEM_Ctx *ctx) {
    if (!ctx) { printf("KEM context: NULL\n"); return; }
    printf("KEM algorithm     : %s\n",   ctx->algorithm);
    printf("  NIST level      : %u\n",   ctx->nist_level);
    printf("  IND-CCA2        : %s\n",   ctx->ind_cca ? "yes" : "no");
    printf("  Public-key len  : %zu B\n", ctx->length_public_key);
    printf("  Secret-key len  : %zu B\n", ctx->length_secret_key);
    printf("  Ciphertext len  : %zu B\n", ctx->length_ciphertext);
    printf("  Shared-secret   : %zu B\n", ctx->length_shared_secret);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SIG — context management
 * ═══════════════════════════════════════════════════════════════════════════ */

PQC_SIG_Ctx *pqc_sig_new(const char *alg) {
    const char *name = alg ? alg : PQC_SIG_DEFAULT;

    OQS_SIG *sig = OQS_SIG_new(name);
    if (!sig) {
        fprintf(stderr, "[pqc] SIG '%s': not available (unknown or disabled at build time)\n", name);
        return NULL;
    }

    PQC_SIG_Ctx *ctx = (PQC_SIG_Ctx *)calloc(1, sizeof(PQC_SIG_Ctx));
    if (!ctx) {
        OQS_SIG_free(sig);
        return NULL;
    }

    ctx->_sig               = sig;
    ctx->algorithm          = sig->method_name;
    ctx->length_public_key  = sig->length_public_key;
    ctx->length_secret_key  = sig->length_secret_key;
    ctx->length_signature   = sig->length_signature;
    ctx->nist_level         = (uint8_t)sig->claimed_nist_level;
    ctx->euf_cma            = sig->euf_cma;
    ctx->suf_cma            = sig->suf_cma;
    ctx->ctx_support        = OQS_SIG_supports_ctx_str(name);
    return ctx;
}

void pqc_sig_free(PQC_SIG_Ctx *ctx) {
    if (!ctx) return;
    OQS_SIG_free(ctx->_sig);
    ctx->_sig = NULL;
    free(ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SIG — key-pair operations
 * ═══════════════════════════════════════════════════════════════════════════ */

PQC_STATUS pqc_sig_keygen(const PQC_SIG_Ctx *ctx, PQC_SIG_Keys *keys) {
    if (!ctx || !ctx->_sig || !keys) return PQC_ERR_NULL;

    memset(keys, 0, sizeof(*keys));
    keys->pk_len = ctx->length_public_key;
    keys->sk_len = ctx->length_secret_key;

    keys->public_key = (uint8_t *)malloc(keys->pk_len);
    keys->secret_key = (uint8_t *)malloc(keys->sk_len);
    if (!keys->public_key || !keys->secret_key) {
        pqc_sig_free_keys(keys);
        return PQC_ERR_ALLOC;
    }

    OQS_STATUS rc = OQS_SIG_keypair(ctx->_sig, keys->public_key, keys->secret_key);
    if (rc != OQS_SUCCESS) {
        pqc_sig_free_keys(keys);
        return PQC_ERR_KEYGEN;
    }
    return PQC_OK;
}

void pqc_sig_free_keys(PQC_SIG_Keys *keys) {
    if (!keys) return;
    _secure_free(&keys->public_key, keys->pk_len);
    _secure_free(&keys->secret_key, keys->sk_len);
    keys->pk_len = keys->sk_len = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SIG — sign / verify
 * ═══════════════════════════════════════════════════════════════════════════ */

PQC_STATUS pqc_sig_sign(const PQC_SIG_Ctx *ctx,
                         const uint8_t     *message,
                         size_t             msg_len,
                         const uint8_t     *sk,
                         PQC_Signature     *sig_out) {
    if (!ctx || !ctx->_sig || !message || !sk || !sig_out) return PQC_ERR_NULL;

    memset(sig_out, 0, sizeof(*sig_out));
    sig_out->data = (uint8_t *)malloc(ctx->length_signature);
    if (!sig_out->data) return PQC_ERR_ALLOC;

    OQS_STATUS rc = OQS_SIG_sign(ctx->_sig,
                                  sig_out->data, &sig_out->len,
                                  message, msg_len,
                                  sk);
    if (rc != OQS_SUCCESS) {
        pqc_sig_free_signature(sig_out);
        return PQC_ERR_SIGN;
    }
    return PQC_OK;
}

PQC_STATUS pqc_sig_sign_ctx(const PQC_SIG_Ctx *ctx,
                              const uint8_t     *message,
                              size_t             msg_len,
                              const uint8_t     *ctx_str,
                              size_t             ctx_str_len,
                              const uint8_t     *sk,
                              PQC_Signature     *sig_out) {
    if (!ctx || !ctx->_sig || !message || !sk || !sig_out) return PQC_ERR_NULL;

    /* Fall back to plain sign when no context string supplied */
    if (!ctx_str || ctx_str_len == 0)
        return pqc_sig_sign(ctx, message, msg_len, sk, sig_out);

    if (!ctx->ctx_support) {
        fprintf(stderr, "[pqc] %s does not support context-string signing\n", ctx->algorithm);
        return PQC_ERR_GENERIC;
    }

    memset(sig_out, 0, sizeof(*sig_out));
    sig_out->data = (uint8_t *)malloc(ctx->length_signature);
    if (!sig_out->data) return PQC_ERR_ALLOC;

    OQS_STATUS rc = OQS_SIG_sign_with_ctx_str(ctx->_sig,
                                               sig_out->data, &sig_out->len,
                                               message, msg_len,
                                               ctx_str, ctx_str_len,
                                               sk);
    if (rc != OQS_SUCCESS) {
        pqc_sig_free_signature(sig_out);
        return PQC_ERR_SIGN;
    }
    return PQC_OK;
}

PQC_STATUS pqc_sig_verify(const PQC_SIG_Ctx *ctx,
                           const uint8_t     *message,
                           size_t             msg_len,
                           const uint8_t     *sig,
                           size_t             sig_len,
                           const uint8_t     *pk) {
    if (!ctx || !ctx->_sig || !message || !sig || !pk) return PQC_ERR_NULL;

    OQS_STATUS rc = OQS_SIG_verify(ctx->_sig, message, msg_len, sig, sig_len, pk);
    return (rc == OQS_SUCCESS) ? PQC_OK : PQC_ERR_VERIFY;
}

void pqc_sig_free_signature(PQC_Signature *sig) {
    if (!sig) return;
    if (sig->data) {
        OQS_MEM_cleanse(sig->data, sig->len);
        free(sig->data);
        sig->data = NULL;
    }
    sig->len = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SIG — introspection utilities
 * ═══════════════════════════════════════════════════════════════════════════ */

void pqc_sig_list_algorithms(void) {
    printf("Available SIG algorithms:\n");
    for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
        const char *name = OQS_SIG_alg_identifier(i);
        if (OQS_SIG_alg_is_enabled(name))
            printf("  [enabled]  %s\n", name);
        else
            printf("  [disabled] %s\n", name);
    }
}

void pqc_sig_print_info(const PQC_SIG_Ctx *ctx) {
    if (!ctx) { printf("SIG context: NULL\n"); return; }
    printf("SIG algorithm     : %s\n",   ctx->algorithm);
    printf("  NIST level      : %u\n",   ctx->nist_level);
    printf("  EUF-CMA         : %s\n",   ctx->euf_cma ? "yes" : "no");
    printf("  SUF-CMA         : %s\n",   ctx->suf_cma ? "yes" : "no");
    printf("  Context strings : %s\n",   ctx->ctx_support ? "yes" : "no");
    printf("  Public-key len  : %zu B\n", ctx->length_public_key);
    printf("  Secret-key len  : %zu B\n", ctx->length_secret_key);
    printf("  Max sig len     : %zu B\n", ctx->length_signature);
}
