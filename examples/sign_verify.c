#include <stdio.h>
#include "sigstore.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file_to_sign> [output.json]\n", argv[0]);
        return 1;
    }

    const char *file_path = argv[1];
    const char *output_path = argc > 2 ? argv[2] : "signature.json";

    printf("=== Signing ===\n");
    printf("File: %s\n", file_path);

    /* Sign the file */
    sigstore_bundle_t *bundle = NULL;
    if (sigstore_sign(file_path, &bundle, 1) != 0) {
        printf("ERROR: Failed to sign file\n");
        return 1;
    }

    printf("Hash: %s\n", bundle->hash);
    printf("Rekor: %s\n", bundle->rekor_success ? "logged" : "not logged");

    /* Write bundle to file */
    if (sigstore_bundle_write(bundle, output_path) != 0) {
        printf("ERROR: Failed to write bundle\n");
        sigstore_bundle_free(bundle);
        return 1;
    }
    printf("Bundle written to: %s\n", output_path);

    sigstore_bundle_free(bundle);

    /* Now verify */
    printf("\n=== Verifying ===\n");

    sigstore_bundle_t *loaded = NULL;
    if (sigstore_bundle_read(output_path, &loaded) != 0) {
        printf("ERROR: Failed to read bundle\n");
        return 1;
    }

    if (sigstore_verify(loaded) == 0) {
        printf("VERIFICATION PASSED\n");
    } else {
        printf("VERIFICATION FAILED\n");
        sigstore_bundle_free(loaded);
        return 1;
    }

    sigstore_bundle_free(loaded);
    return 0;
}
