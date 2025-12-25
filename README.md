# sigstore-c

A C library for signing files and logging to the [Sigstore](https://sigstore.dev) Rekor transparency log.

## Features

- Sign files with ECDSA P-256 ephemeral keys
- Verify signatures
- Log signatures to Rekor transparency log
- Read/write JSON signature bundles

## Dependencies

- OpenSSL (libssl, libcrypto)
- libcurl

### Install on Debian/Ubuntu

```bash
sudo apt install libssl-dev libcurl4-openssl-dev
```

### Install on Arch Linux

```bash
sudo pacman -S openssl curl
```

## Building

```bash
make
```

This creates:
- `libsigstore.a` - static library
- `libsigstore.so` - shared library

## Installation

```bash
sudo make install
```

## Usage

### Link against the library

```bash
gcc -o myprogram myprogram.c -lsigstore -lcrypto -lssl -lcurl
```

### API

```c
#include <sigstore.h>

/* Sign a file */
sigstore_bundle_t *bundle = NULL;
sigstore_sign("myfile.txt", &bundle, 1);  /* 1 = log to Rekor */

/* Write bundle to JSON */
sigstore_bundle_write(bundle, "signature.json");
sigstore_bundle_free(bundle);

/* Read and verify */
sigstore_bundle_t *loaded = NULL;
sigstore_bundle_read("signature.json", &loaded);

if (sigstore_verify(loaded) == 0) {
    printf("Verified!\n");
}

sigstore_bundle_free(loaded);
```

### Example

```bash
make example
./examples/sign_verify myfile.txt
```

## Bundle Format

```json
{
  "version": "1.0",
  "file": "path/to/file",
  "hash": {
    "algorithm": "sha256",
    "value": "..."
  },
  "signature": "<base64>",
  "publicKey": "<base64>",
  "rekor": { /* transparency log entry */ }
}
```

## License

MIT
