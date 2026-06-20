/**
 * @file pqc_abstract.h
 * @brief Post-Quantum Cryptography Abstract Layer over liboqs
 *
 * This header provides a simplified, unified API over liboqs that hides
 * raw memory management, error-code plumbing, and algorithm-specific
 * constants behind clean, safe interfaces.
 *
 * Two subsystems are exposed:
 *  - PQC_KEM  — Key Encapsulation Mechanism  (e.g. ML-KEM, Kyber, BIKE …)
 *  - PQC_SIG  — Digital Signature Scheme     (e.g. ML-DSA, Falcon, SLH-DSA …)
 *
 * Both follow the same lifecycle:
 *   1. pqc_kem_new() / pqc_sig_new()      — create context
 *   2. pqc_kem_keygen() / pqc_sig_keygen()— generate keypair (heap-allocated)
 *   3. pqc_kem_encaps() / pqc_sig_sign()  — use the keys
 *   4. pqc_kem_decaps()/ pqc_sig_verify() — use the keys
 *   5. pqc_kem_free_keys() / pqc_sig_free_keys() — zeroize & release key bytes
 *   6. pqc_kem_free() / pqc_sig_free()    — destroy context
 *
 * Recommended default algorithms:
 *   KEM : "ML-KEM-768"   (NIST level 3, IND-CCA2, FIPS 203)
 *   SIG : "ML-DSA-65"    (NIST level 3, EUF-CMA,  FIPS 204)
 *
 * Build:
 *   gcc -o myapp myapp.c pqc_abstract.c \
 *       -I/usr/local/include -L/usr/local/lib -loqs -lm
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PQC_ABSTRACT_H
#define PQC_ABSTRACT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* ── forward-declare the liboqs types we wrap ─────────────────────────────── */
typedef struct OQS_KEM OQS_KEM;
typedef struct OQS_SIG OQS_SIG;

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Return codes
 * ═══════════════════════════════════════════════════════════════════════════ */
typedef enum {
    PQC_OK              =  0,  /**< Operation succeeded.                    */
    PQC_ERR_GENERIC     = -1,  /**< Unspecified error.                      */
    PQC_ERR_NULL        = -2,  /**< NULL argument or uninitialised context. */
    PQC_ERR_ALG_UNKNOWN = -3,  /**< Algorithm name not recognised.          */
    PQC_ERR_ALG_DISABLED= -4,  /**< Algorithm disabled at compile time.     */
    PQC_ERR_KEYGEN      = -5,  /**< Key-generation failure.                 */
    PQC_ERR_ENCAPS      = -6,  /**< Encapsulation failure.                  */
    PQC_ERR_DECAPS      = -7,  /**< Decapsulation failure.                  */
    PQC_ERR_SIGN        = -8,  /**< Signing failure.                        */
    PQC_ERR_VERIFY      = -9,  /**< Signature invalid.                      */
    PQC_ERR_ALLOC       = -10, /**< Memory allocation failure.              */
} PQC_STATUS;

/* ═══════════════════════════════════════════════════════════════════════════
 * Well-known algorithm name constants
 * ═══════════════════════════════════════════════════════════════════════════ */

/* --- KEM aliases ---------------------------------------------------------- */
#define PQC_KEM_DEFAULT          "ML-KEM-768"
#define PQC_KEM_ML_KEM_512       "ML-KEM-512"
#define PQC_KEM_ML_KEM_768       "ML-KEM-768"
#define PQC_KEM_ML_KEM_1024      "ML-KEM-1024"
#define PQC_KEM_KYBER_512        "Kyber512"
#define PQC_KEM_KYBER_768        "Kyber768"
#define PQC_KEM_KYBER_1024       "Kyber1024"
#define PQC_KEM_BIKE_L1          "BIKE-L1"
#define PQC_KEM_BIKE_L3          "BIKE-L3"
#define PQC_KEM_FRODOKEM_640_AES "FrodoKEM-640-AES"
#define PQC_KEM_HQC_1            "HQC-1"

/* --- SIG aliases ---------------------------------------------------------- */
#define PQC_SIG_DEFAULT          "ML-DSA-65"
#define PQC_SIG_ML_DSA_44        "ML-DSA-44"
#define PQC_SIG_ML_DSA_65        "ML-DSA-65"
#define PQC_SIG_ML_DSA_87        "ML-DSA-87"
#define PQC_SIG_FALCON_512       "Falcon-512"
#define PQC_SIG_FALCON_1024      "Falcon-1024"
#define PQC_SIG_SPHINCS_SHA2_128S "SLH_DSA_PURE_SHA2_128S"

/* ═══════════════════════════════════════════════════════════════════════════
 * Key-pair structures
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Heap-allocated KEM key pair. Free with pqc_kem_free_keys(). */
typedef struct {
    uint8_t *public_key;    /**< Public key bytes  (length = ctx->length_public_key). */
    uint8_t *secret_key;    /**< Secret key bytes  (length = ctx->length_secret_key). */
    size_t   pk_len;        /**< Byte length of public_key. */
    size_t   sk_len;        /**< Byte length of secret_key. */
} PQC_KEM_Keys;

/** Heap-allocated SIG key pair. Free with pqc_sig_free_keys(). */
typedef struct {
    uint8_t *public_key;    /**< Public key bytes  (length = ctx->length_public_key). */
    uint8_t *secret_key;    /**< Secret key bytes  (length = ctx->length_secret_key). */
    size_t   pk_len;
    size_t   sk_len;
} PQC_SIG_Keys;

/** Heap-allocated encapsulation result. Free with pqc_kem_free_encaps(). */
typedef struct {
    uint8_t *ciphertext;    /**< Encapsulated key (KEM ciphertext). */
    uint8_t *shared_secret; /**< Derived shared secret.             */
    size_t   ct_len;
    size_t   ss_len;
} PQC_KEM_Encaps;

/** Heap-allocated signature. Free with pqc_sig_free_signature(). */
typedef struct {
    uint8_t *data;          /**< Signature bytes.  */
    size_t   len;           /**< Actual byte count.*/
} PQC_Signature;

/* ═══════════════════════════════════════════════════════════════════════════
 * KEM context
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Opaque KEM context. Obtain with pqc_kem_new(). */
typedef struct {
    OQS_KEM    *_kem;               /**< Internal liboqs handle (do not touch). */
    const char *algorithm;          /**< Algorithm name string.                 */
    size_t      length_public_key;
    size_t      length_secret_key;
    size_t      length_ciphertext;
    size_t      length_shared_secret;
    uint8_t     nist_level;         /**< NIST security level (1-5).             */
    bool        ind_cca;            /**< IND-CCA2 if true, IND-CPA otherwise.   */
} PQC_KEM_Ctx;

/**
 * @brief Create a KEM context for the named algorithm.
 *
 * @param alg  Algorithm name (e.g. PQC_KEM_DEFAULT).
 *             Pass NULL to use PQC_KEM_DEFAULT.
 * @return     Heap-allocated context or NULL on failure.
 */
PQC_KEM_Ctx *pqc_kem_new(const char *alg);

/**
 * @brief Generate a KEM key pair.
 *
 * @param ctx   Initialised KEM context.
 * @param keys  Output structure; caller must call pqc_kem_free_keys() when done.
 * @return      PQC_OK or a PQC_ERR_* code.
 */
PQC_STATUS pqc_kem_keygen(const PQC_KEM_Ctx *ctx, PQC_KEM_Keys *keys);

/**
 * @brief Encapsulate: generate ciphertext + shared secret from a public key.
 *
 * @param ctx     Initialised KEM context.
 * @param pk      Public key (ctx->length_public_key bytes).
 * @param result  Output; caller must call pqc_kem_free_encaps() when done.
 * @return        PQC_OK or a PQC_ERR_* code.
 */
PQC_STATUS pqc_kem_encaps(const PQC_KEM_Ctx *ctx,
                           const uint8_t     *pk,
                           PQC_KEM_Encaps    *result);

/**
 * @brief Decapsulate: recover shared secret from ciphertext + secret key.
 *
 * @param ctx           Initialised KEM context.
 * @param ciphertext    Ciphertext from pqc_kem_encaps().
 * @param sk            Secret key (ctx->length_secret_key bytes).
 * @param shared_secret Output buffer — caller allocates ctx->length_shared_secret bytes.
 * @return              PQC_OK or a PQC_ERR_* code.
 */
PQC_STATUS pqc_kem_decaps(const PQC_KEM_Ctx *ctx,
                           const uint8_t     *ciphertext,
                           const uint8_t     *sk,
                           uint8_t           *shared_secret);

/** Zero out and free KEM keys. Safe to call with NULL pointers. */
void pqc_kem_free_keys(PQC_KEM_Keys *keys);

/** Zero out and free an encapsulation result. */
void pqc_kem_free_encaps(PQC_KEM_Encaps *e);

/** Destroy a KEM context. */
void pqc_kem_free(PQC_KEM_Ctx *ctx);

/* ═══════════════════════════════════════════════════════════════════════════
 * SIG context
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Opaque SIG context. Obtain with pqc_sig_new(). */
typedef struct {
    OQS_SIG    *_sig;
    const char *algorithm;
    size_t      length_public_key;
    size_t      length_secret_key;
    size_t      length_signature;   /**< Maximum signature length. */
    uint8_t     nist_level;
    bool        euf_cma;
    bool        suf_cma;
    bool        ctx_support;        /**< Supports context-string signing. */
} PQC_SIG_Ctx;

/**
 * @brief Create a SIG context for the named algorithm.
 *
 * @param alg  Algorithm name (e.g. PQC_SIG_DEFAULT).
 *             Pass NULL to use PQC_SIG_DEFAULT.
 * @return     Heap-allocated context or NULL on failure.
 */
PQC_SIG_Ctx *pqc_sig_new(const char *alg);

/**
 * @brief Generate a signature key pair.
 *
 * @param ctx   Initialised SIG context.
 * @param keys  Output; caller must call pqc_sig_free_keys() when done.
 * @return      PQC_OK or a PQC_ERR_* code.
 */
PQC_STATUS pqc_sig_keygen(const PQC_SIG_Ctx *ctx, PQC_SIG_Keys *keys);

/**
 * @brief Sign a message.
 *
 * @param ctx        Initialised SIG context.
 * @param message    Message bytes.
 * @param msg_len    Length of message.
 * @param sk         Secret key (ctx->length_secret_key bytes).
 * @param sig_out    Output; caller must call pqc_sig_free_signature() when done.
 * @return           PQC_OK or a PQC_ERR_* code.
 */
PQC_STATUS pqc_sig_sign(const PQC_SIG_Ctx *ctx,
                         const uint8_t     *message,
                         size_t             msg_len,
                         const uint8_t     *sk,
                         PQC_Signature     *sig_out);

/**
 * @brief Sign a message with a context string (for algorithms that support it).
 *
 * Falls back to plain signing if ctx_support == false and ctx_str_len == 0.
 *
 * @param ctx        Initialised SIG context.
 * @param message    Message bytes.
 * @param msg_len    Length of message.
 * @param ctx_str    Context string (may be NULL).
 * @param ctx_str_len Length of context string (0 if not used).
 * @param sk         Secret key.
 * @param sig_out    Output signature; caller must call pqc_sig_free_signature().
 * @return           PQC_OK or a PQC_ERR_* code.
 */
PQC_STATUS pqc_sig_sign_ctx(const PQC_SIG_Ctx *ctx,
                              const uint8_t     *message,
                              size_t             msg_len,
                              const uint8_t     *ctx_str,
                              size_t             ctx_str_len,
                              const uint8_t     *sk,
                              PQC_Signature     *sig_out);

/**
 * @brief Verify a signature.
 *
 * @param ctx       Initialised SIG context.
 * @param message   The original message.
 * @param msg_len   Length of message.
 * @param sig       Signature bytes.
 * @param sig_len   Length of signature.
 * @param pk        Public key (ctx->length_public_key bytes).
 * @return          PQC_OK if valid, PQC_ERR_VERIFY if invalid, other codes on error.
 */
PQC_STATUS pqc_sig_verify(const PQC_SIG_Ctx *ctx,
                           const uint8_t     *message,
                           size_t             msg_len,
                           const uint8_t     *sig,
                           size_t             sig_len,
                           const uint8_t     *pk);

/** Zero out and free SIG keys. Safe to call with NULL pointers. */
void pqc_sig_free_keys(PQC_SIG_Keys *keys);

/** Free a signature buffer. */
void pqc_sig_free_signature(PQC_Signature *sig);

/** Destroy a SIG context. */
void pqc_sig_free(PQC_SIG_Ctx *ctx);

/* ═══════════════════════════════════════════════════════════════════════════
 * Utility
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * @brief Initialise the liboqs library (calls OQS_init internally).
 *
 * Must be called once before any other pqc_* function.
 */
void pqc_init(void);

/**
 * @brief Tear down the liboqs library (calls OQS_destroy internally).
 */
void pqc_destroy(void);

/**
 * @brief Human-readable string for a PQC_STATUS code.
 */
const char *pqc_status_str(PQC_STATUS s);

/**
 * @brief List all available KEM algorithm names to stdout.
 */
void pqc_kem_list_algorithms(void);

/**
 * @brief List all available SIG algorithm names to stdout.
 */
void pqc_sig_list_algorithms(void);

/**
 * @brief Print KEM context info to stdout.
 */
void pqc_kem_print_info(const PQC_KEM_Ctx *ctx);

/**
 * @brief Print SIG context info to stdout.
 */
void pqc_sig_print_info(const PQC_SIG_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* PQC_ABSTRACT_H */
