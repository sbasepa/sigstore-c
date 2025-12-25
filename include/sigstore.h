#ifndef SIGSTORE_H
#define SIGSTORE_H

#include <stddef.h>

/* Signature bundle containing all verification data */
typedef struct {
    char *file_path;      /* Path to signed file */
    char *hash;           /* SHA256 hash (hex string) */
    char *signature;      /* Base64-encoded signature */
    char *public_key;     /* Base64-encoded PEM public key */
    char *rekor_response; /* Rekor transparency log response (JSON) */
    int rekor_success;    /* 1 if logged to Rekor, 0 otherwise */
} sigstore_bundle_t;

/* Sign a file and optionally log to Rekor transparency log.
 *
 * Parameters:
 *   file_path  - Path to file to sign
 *   bundle     - Output bundle (caller must free with sigstore_bundle_free)
 *   use_rekor  - If non-zero, submit to Rekor transparency log
 *
 * Returns: 0 on success, non-zero on error
 */
int sigstore_sign(const char *file_path, sigstore_bundle_t **bundle, int use_rekor);

/* Verify a signature bundle.
 *
 * Parameters:
 *   bundle - Signature bundle to verify
 *
 * Returns: 0 if verification passes, non-zero on failure
 */
int sigstore_verify(const sigstore_bundle_t *bundle);

/* Write signature bundle to JSON file.
 *
 * Parameters:
 *   bundle      - Bundle to write
 *   output_path - Output file path
 *
 * Returns: 0 on success, non-zero on error
 */
int sigstore_bundle_write(const sigstore_bundle_t *bundle, const char *output_path);

/* Read signature bundle from JSON file.
 *
 * Parameters:
 *   path   - Path to JSON bundle file
 *   bundle - Output bundle (caller must free with sigstore_bundle_free)
 *
 * Returns: 0 on success, non-zero on error
 */
int sigstore_bundle_read(const char *path, sigstore_bundle_t **bundle);

/* Free a signature bundle */
void sigstore_bundle_free(sigstore_bundle_t *bundle);

/* Hash a file (SHA256).
 *
 * Parameters:
 *   file_path - Path to file
 *   hash_out  - Output hex string (caller must free)
 *
 * Returns: 0 on success, non-zero on error
 */
int sigstore_hash_file(const char *file_path, char **hash_out);

#endif /* SIGSTORE_H */
