#include "sigstore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <curl/curl.h>

#define HASH_BUFFER_SIZE 4096
#define SHA256_DIGEST_LENGTH 32

/* HTTP response buffer */
struct http_response {
    char *memory;
    size_t size;
};

static size_t http_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct http_response *mem = (struct http_response *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

/* Base64 encoding */
static char *base64_encode(const unsigned char *src, size_t len) {
    static const unsigned char table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t olen = len * 4 / 3 + 4 + 1;
    if (olen < len) return NULL;

    unsigned char *out = malloc(olen);
    if (!out) return NULL;

    unsigned char *pos = out;
    const unsigned char *end = src + len;
    const unsigned char *in = src;

    while (end - in >= 3) {
        *pos++ = table[in[0] >> 2];
        *pos++ = table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in) {
        *pos++ = table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
    }

    *pos = '\0';
    return (char*)out;
}

/* Base64 decoding */
static int base64_decode(const char *src, size_t srcLen, unsigned char **out, size_t *outLen) {
    static const unsigned char decode_table[256] = {
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
        52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
        64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64
    };

    size_t padding = 0;
    if (srcLen > 0 && src[srcLen - 1] == '=') padding++;
    if (srcLen > 1 && src[srcLen - 2] == '=') padding++;

    size_t decodedLen = (srcLen * 3) / 4 - padding;
    unsigned char *decoded = malloc(decodedLen + 1);
    if (!decoded) return -1;

    size_t j = 0;
    for (size_t i = 0; i < srcLen; ) {
        unsigned int a = src[i] == '=' ? 0 : decode_table[(unsigned char)src[i]]; i++;
        unsigned int b = src[i] == '=' ? 0 : decode_table[(unsigned char)src[i]]; i++;
        unsigned int c = src[i] == '=' ? 0 : decode_table[(unsigned char)src[i]]; i++;
        unsigned int d = src[i] == '=' ? 0 : decode_table[(unsigned char)src[i]]; i++;
        unsigned int triple = (a << 18) | (b << 12) | (c << 6) | d;
        if (j < decodedLen) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < decodedLen) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < decodedLen) decoded[j++] = triple & 0xFF;
    }

    *out = decoded;
    *outLen = decodedLen;
    return 0;
}

/* Hash file to raw bytes */
static int hash_file_raw(const char *file_path, unsigned char *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    FILE *file = fopen(file_path, "rb");
    if (!file) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    /* Include file path in hash */
    if (EVP_DigestUpdate(ctx, file_path, strlen(file_path)) != 1) {
        fclose(file);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    char buffer[HASH_BUFFER_SIZE];
    int bytesRead;
    while ((bytesRead = fread(buffer, 1, HASH_BUFFER_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytesRead) != 1) {
            fclose(file);
            EVP_MD_CTX_free(ctx);
            return -1;
        }
    }
    fclose(file);

    unsigned int digestLen;
    if (EVP_DigestFinal_ex(ctx, out, &digestLen) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return (int)digestLen;
}

int sigstore_hash_file(const char *file_path, char **hash_out) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int digestLen = hash_file_raw(file_path, digest);
    if (digestLen < 0) return -1;

    char *hexHash = malloc(digestLen * 2 + 1);
    if (!hexHash) return -1;

    for (int i = 0; i < digestLen; i++) {
        sprintf(hexHash + (i * 2), "%02x", digest[i]);
    }
    hexHash[digestLen * 2] = '\0';

    *hash_out = hexHash;
    return 0;
}

/* Generate ECDSA P-256 keypair */
static EVP_PKEY *generate_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return NULL;

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Submit to Rekor transparency log */
static int submit_to_rekor(const char *sig64, const char *pub64, const char *hash, char **response) {
    const char *fmt = "{\n\"kind\": \"hashedrekord\",\n\"apiVersion\": \"0.0.1\",\n\"spec\": {\n\"signature\": {\n\"content\": \"%s\",\n\"publicKey\": {\n\"content\": \"%s\"\n}\n},\n\"data\": {\n\"hash\": {\n\"algorithm\": \"sha256\",\n\"value\": \"%s\"\n}\n}\n}\n}";

    int json_len = snprintf(NULL, 0, fmt, sig64, pub64, hash) + 1;
    char *json = malloc(json_len);
    if (!json) return -1;
    snprintf(json, json_len, fmt, sig64, pub64, hash);

    struct http_response resp = {.memory = malloc(1), .size = 0};

    CURL *curl = curl_easy_init();
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, "https://rekor.sigstore.dev/api/v1/log/entries");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)(json_len - 1));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "sigstore-c/1.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

    CURLcode ret = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(json);

    if (ret != CURLE_OK || http_code != 201) {
        free(resp.memory);
        return -1;
    }

    *response = resp.memory;
    return 0;
}

int sigstore_sign(const char *file_path, sigstore_bundle_t **bundle, int use_rekor) {
    sigstore_bundle_t *b = calloc(1, sizeof(sigstore_bundle_t));
    if (!b) return -1;

    /* Hash file */
    unsigned char rawHash[SHA256_DIGEST_LENGTH];
    if (hash_file_raw(file_path, rawHash) < 0) {
        sigstore_bundle_free(b);
        return -1;
    }

    if (sigstore_hash_file(file_path, &b->hash) != 0) {
        sigstore_bundle_free(b);
        return -1;
    }

    b->file_path = strdup(file_path);
    if (!b->file_path) {
        sigstore_bundle_free(b);
        return -1;
    }

    /* Generate keypair */
    EVP_PKEY *pkey = generate_keypair();
    if (!pkey) {
        sigstore_bundle_free(b);
        return -1;
    }

    /* Sign */
    EVP_PKEY_CTX *signCtx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!signCtx || EVP_PKEY_sign_init(signCtx) <= 0) {
        EVP_PKEY_CTX_free(signCtx);
        EVP_PKEY_free(pkey);
        sigstore_bundle_free(b);
        return -1;
    }

    size_t sigLen = 0;
    EVP_PKEY_sign(signCtx, NULL, &sigLen, rawHash, SHA256_DIGEST_LENGTH);
    unsigned char *sig = malloc(sigLen);
    if (!sig || EVP_PKEY_sign(signCtx, sig, &sigLen, rawHash, SHA256_DIGEST_LENGTH) <= 0) {
        free(sig);
        EVP_PKEY_CTX_free(signCtx);
        EVP_PKEY_free(pkey);
        sigstore_bundle_free(b);
        return -1;
    }
    EVP_PKEY_CTX_free(signCtx);

    b->signature = base64_encode(sig, sigLen);
    free(sig);

    /* Export public key as PEM */
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio || !PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        sigstore_bundle_free(b);
        return -1;
    }

    char *pemData;
    long pemLen = BIO_get_mem_data(bio, &pemData);
    b->public_key = base64_encode((unsigned char*)pemData, pemLen);
    BIO_free(bio);
    EVP_PKEY_free(pkey);

    if (!b->signature || !b->public_key) {
        sigstore_bundle_free(b);
        return -1;
    }

    /* Submit to Rekor if requested */
    if (use_rekor) {
        if (submit_to_rekor(b->signature, b->public_key, b->hash, &b->rekor_response) == 0) {
            b->rekor_success = 1;
        }
    }

    *bundle = b;
    return 0;
}

int sigstore_verify(const sigstore_bundle_t *bundle) {
    if (!bundle || !bundle->file_path || !bundle->hash ||
        !bundle->signature || !bundle->public_key) {
        return -1;
    }

    /* Verify hash */
    char *actualHash;
    if (sigstore_hash_file(bundle->file_path, &actualHash) != 0) {
        return -1;
    }

    if (strcmp(bundle->hash, actualHash) != 0) {
        free(actualHash);
        return -1;  /* Hash mismatch */
    }
    free(actualHash);

    /* Decode public key */
    unsigned char *pemData;
    size_t pemLen;
    if (base64_decode(bundle->public_key, strlen(bundle->public_key), &pemData, &pemLen) < 0) {
        return -1;
    }

    BIO *bio = BIO_new_mem_buf(pemData, (int)pemLen);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(pemData);

    if (!pkey) return -1;

    /* Decode signature */
    unsigned char *sig;
    size_t sigLen;
    if (base64_decode(bundle->signature, strlen(bundle->signature), &sig, &sigLen) < 0) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    /* Verify signature */
    unsigned char rawHash[SHA256_DIGEST_LENGTH];
    if (hash_file_raw(bundle->file_path, rawHash) < 0) {
        free(sig);
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        free(sig);
        EVP_PKEY_free(pkey);
        return -1;
    }

    int result = EVP_PKEY_verify(ctx, sig, sigLen, rawHash, SHA256_DIGEST_LENGTH);
    EVP_PKEY_CTX_free(ctx);
    free(sig);
    EVP_PKEY_free(pkey);

    return (result == 1) ? 0 : -1;
}

int sigstore_bundle_write(const sigstore_bundle_t *bundle, const char *output_path) {
    FILE *f = fopen(output_path, "w");
    if (!f) return -1;

    fprintf(f, "{\n");
    fprintf(f, "  \"version\": \"1.0\",\n");
    fprintf(f, "  \"file\": \"%s\",\n", bundle->file_path);
    fprintf(f, "  \"hash\": {\n");
    fprintf(f, "    \"algorithm\": \"sha256\",\n");
    fprintf(f, "    \"value\": \"%s\"\n", bundle->hash);
    fprintf(f, "  },\n");
    fprintf(f, "  \"signature\": \"%s\",\n", bundle->signature);
    fprintf(f, "  \"publicKey\": \"%s\",\n", bundle->public_key);
    fprintf(f, "  \"rekor\": %s\n", bundle->rekor_response ? bundle->rekor_response : "null");
    fprintf(f, "}\n");

    fclose(f);
    return 0;
}

/* Simple JSON string extraction */
static char *json_get_string(const char *json, const char *key) {
    char searchKey[256];
    snprintf(searchKey, sizeof(searchKey), "\"%s\":", key);

    const char *pos = strstr(json, searchKey);
    if (!pos) return NULL;

    pos += strlen(searchKey);
    while (*pos == ' ' || *pos == '\n' || *pos == '\t') pos++;

    if (*pos != '"') return NULL;
    pos++;

    const char *end = pos;
    while (*end && *end != '"') {
        if (*end == '\\' && *(end + 1)) end += 2;
        else end++;
    }

    size_t len = end - pos;
    char *value = malloc(len + 1);
    if (!value) return NULL;
    memcpy(value, pos, len);
    value[len] = '\0';
    return value;
}

static char *json_get_hash_value(const char *json) {
    const char *hashObj = strstr(json, "\"hash\":");
    if (!hashObj) return NULL;
    return json_get_string(hashObj, "value");
}

int sigstore_bundle_read(const char *path, sigstore_bundle_t **bundle) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *json = malloc(len + 1);
    if (!json) {
        fclose(f);
        return -1;
    }

    fread(json, 1, len, f);
    fclose(f);
    json[len] = '\0';

    sigstore_bundle_t *b = calloc(1, sizeof(sigstore_bundle_t));
    if (!b) {
        free(json);
        return -1;
    }

    b->file_path = json_get_string(json, "file");
    b->hash = json_get_hash_value(json);
    b->signature = json_get_string(json, "signature");
    b->public_key = json_get_string(json, "publicKey");

    /* Check for rekor entry */
    if (strstr(json, "\"rekor\": null") == NULL && strstr(json, "\"rekor\":null") == NULL) {
        const char *rekorStart = strstr(json, "\"rekor\":");
        if (rekorStart) {
            rekorStart += 8;
            while (*rekorStart == ' ' || *rekorStart == '\n') rekorStart++;
            /* Simple extraction - find matching brace */
            if (*rekorStart == '{') {
                int depth = 1;
                const char *end = rekorStart + 1;
                while (*end && depth > 0) {
                    if (*end == '{') depth++;
                    else if (*end == '}') depth--;
                    end++;
                }
                size_t rekorLen = end - rekorStart;
                b->rekor_response = malloc(rekorLen + 1);
                if (b->rekor_response) {
                    memcpy(b->rekor_response, rekorStart, rekorLen);
                    b->rekor_response[rekorLen] = '\0';
                    b->rekor_success = 1;
                }
            }
        }
    }

    free(json);

    if (!b->file_path || !b->hash || !b->signature || !b->public_key) {
        sigstore_bundle_free(b);
        return -1;
    }

    *bundle = b;
    return 0;
}

void sigstore_bundle_free(sigstore_bundle_t *bundle) {
    if (!bundle) return;
    free(bundle->file_path);
    free(bundle->hash);
    free(bundle->signature);
    free(bundle->public_key);
    free(bundle->rekor_response);
    free(bundle);
}
