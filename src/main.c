#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fileformat.h"
#include "kdf.h"
#include "makocrypto/makocrypto.h"

static void print_usage(const char *prog_name) {
    fprintf(stderr,
        "Makocrypto - block cipher file encryption\n\n"
        "Usage:\n"
        "  %s encrypt -i <input> -o <output> -p <passphrase> [-k 128|256]\n"
        "  %s decrypt -i <input> -o <output> -p <passphrase>\n\n"
        "Options:\n"
        "  -i <path>        Input file path\n"
        "  -o <path>        Output file path\n"
        "  -p <passphrase>  Passphrase used to derive the encryption key\n"
        "  -k <128|256>     Key size in bits for encryption (default: 256)\n",
        prog_name, prog_name);
}

static uint8_t *read_entire_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);

    uint8_t *buf = malloc((size_t)size > 0 ? (size_t)size : 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }

    size_t read_bytes = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (read_bytes != (size_t)size) {
        free(buf);
        return NULL;
    }

    *out_len = (size_t)size;
    return buf;
}

static int write_entire_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return (written == len) ? 0 : -1;
}

/*
 * Encrypts using format version 2: GCM mode with a per-file random KDF
 * salt and GCM nonce. This is the only format this CLI ever writes.
 */
static int do_encrypt(const char *input_path, const char *output_path,
                       const char *passphrase, mako_key_size_t key_size) {
    size_t plaintext_len = 0;
    uint8_t *plaintext = read_entire_file(input_path, &plaintext_len);
    if (plaintext == NULL) {
        fprintf(stderr, "Error: could not read input file '%s'\n", input_path);
        return 1;
    }

    uint8_t salt[MAKO_KDF_SALT_SIZE];
    if (mako_random_bytes(salt, sizeof(salt)) != MAKO_OK) {
        fprintf(stderr, "Error: failed to generate a secure salt\n");
        free(plaintext);
        return 1;
    }

    uint8_t key[MAKO_KEY256_BYTES];
    size_t key_bytes = (key_size == MAKO_KEY_128) ? MAKO_KEY128_BYTES : MAKO_KEY256_BYTES;
    mako_kdf_derive((const uint8_t *)passphrase, strlen(passphrase), salt,
                     key, key_bytes);

    mako_key_schedule_t ks;
    if (mako_key_init(key, key_size, &ks) != MAKO_OK) {
        fprintf(stderr, "Error: key initialization failed\n");
        free(plaintext);
        return 1;
    }

    mako_file_header_v2_t header;
    memcpy(header.magic, MAKO_MAGIC, MAKO_MAGIC_LEN);
    header.version = MAKO_FORMAT_VERSION_2;
    header.key_size_flag = (key_size == MAKO_KEY_128) ? 0 : 1;
    memcpy(header.salt, salt, MAKO_KDF_SALT_SIZE);

    if (mako_random_bytes(header.nonce, MAKO_GCM_NONCE_SIZE) != MAKO_OK) {
        fprintf(stderr, "Error: failed to generate a secure nonce\n");
        free(plaintext);
        return 1;
    }

    /* Serialize the fixed-size header fields (everything except the tag,
     * which is appended after encryption once it's known) up front, so
     * the exact same bytes can be passed to mako_gcm_encrypt() as
     * associated data. This authenticates the header itself -- the
     * format version and key-size flag in particular -- alongside the
     * ciphertext, under one tag. */
    uint8_t header_bytes[MAKO_HEADER_V2_FIELDS_SIZE];
    size_t off = 0;
    memcpy(header_bytes + off, header.magic, MAKO_MAGIC_LEN);
    off += MAKO_MAGIC_LEN;
    header_bytes[off++] = header.version;
    header_bytes[off++] = header.key_size_flag;
    memcpy(header_bytes + off, header.salt, MAKO_KDF_SALT_SIZE);
    off += MAKO_KDF_SALT_SIZE;
    memcpy(header_bytes + off, header.nonce, MAKO_GCM_NONCE_SIZE);
    off += MAKO_GCM_NONCE_SIZE;

    uint8_t *ciphertext = malloc(plaintext_len > 0 ? plaintext_len : 1);
    if (ciphertext == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        free(plaintext);
        return 1;
    }

    uint8_t tag[MAKO_GCM_TAG_SIZE];
    mako_status_t status = mako_gcm_encrypt(&ks, plaintext, plaintext_len,
                                             header.nonce, header_bytes,
                                             sizeof(header_bytes), ciphertext,
                                             plaintext_len > 0 ? plaintext_len : 1,
                                             tag);
    free(plaintext);

    if (status != MAKO_OK) {
        fprintf(stderr, "Error: encryption failed\n");
        free(ciphertext);
        return 1;
    }

    size_t total_len = MAKO_HEADER_V2_SIZE + plaintext_len;
    uint8_t *out_buf = malloc(total_len);
    if (out_buf == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        free(ciphertext);
        return 1;
    }

    memcpy(out_buf, header_bytes, MAKO_HEADER_V2_FIELDS_SIZE);
    memcpy(out_buf + MAKO_HEADER_V2_FIELDS_SIZE, tag, MAKO_GCM_TAG_SIZE);
    memcpy(out_buf + MAKO_HEADER_V2_SIZE, ciphertext, plaintext_len);
    free(ciphertext);

    int result = write_entire_file(output_path, out_buf, total_len);
    free(out_buf);

    if (result != 0) {
        fprintf(stderr, "Error: could not write output file '%s'\n", output_path);
        return 1;
    }

    printf("Encrypted '%s' -> '%s' (%zu bytes, %d-bit key, format v2/GCM)\n",
           input_path, output_path, total_len, (int)key_size);
    return 0;
}

/*
 * Decrypts a version-1 (CBC) file. Kept solely for backward
 * compatibility with files encrypted before format version 2 existed --
 * see docs/SECURITY.md for why CBC-without-a-MAC should never be used
 * for new encryption. This path is unreachable from do_encrypt(); it is
 * only ever entered from do_decrypt() after reading a version byte of 1
 * from an existing file.
 */
static int do_decrypt_v1(const uint8_t *file_data, size_t file_len,
                          const char *passphrase, const char *input_path,
                          const char *output_path) {
    if (file_len < MAKO_HEADER_V1_SIZE) {
        fprintf(stderr, "Error: decryption failed\n");
        return 1;
    }

    uint8_t key_size_flag = file_data[MAKO_MAGIC_LEN + 1];
    mako_key_size_t key_size = (key_size_flag == 0) ? MAKO_KEY_128 : MAKO_KEY_256;

    uint8_t iv[MAKO_IV_SIZE];
    memcpy(iv, file_data + MAKO_MAGIC_LEN + 2, MAKO_IV_SIZE);

    const uint8_t *ciphertext = file_data + MAKO_HEADER_V1_SIZE;
    size_t ciphertext_len = file_len - MAKO_HEADER_V1_SIZE;

    if (ciphertext_len == 0 || ciphertext_len % MAKO_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: decryption failed\n");
        return 1;
    }

    /* Version 1 predates the salted KDF, so it is derived here with an
     * all-zero salt: this reproduces exactly what version 1 used to do
     * (the pre-salt mako_kdf_derive() always absorbed the passphrase
     * alone), which is required for old files to still decrypt
     * correctly, and is safe to hardcode here specifically because this
     * code path is only ever reached for pre-existing version-1 files,
     * never for new encryption -- do_encrypt() always takes the version-2
     * path with a fresh random salt. */
    uint8_t zero_salt[MAKO_KDF_SALT_SIZE] = {0};
    uint8_t key[MAKO_KEY256_BYTES];
    size_t key_bytes = (key_size == MAKO_KEY_128) ? MAKO_KEY128_BYTES : MAKO_KEY256_BYTES;
    mako_kdf_derive((const uint8_t *)passphrase, strlen(passphrase), zero_salt,
                     key, key_bytes);

    mako_key_schedule_t ks;
    if (mako_key_init(key, key_size, &ks) != MAKO_OK) {
        fprintf(stderr, "Error: decryption failed\n");
        return 1;
    }

    uint8_t *plaintext = malloc(ciphertext_len);
    if (plaintext == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        return 1;
    }

    size_t plaintext_len = 0;
    mako_status_t status = mako_cbc_decrypt(&ks, ciphertext, ciphertext_len,
                                             iv, plaintext, ciphertext_len,
                                             &plaintext_len);

    if (status != MAKO_OK) {
        /* Deliberately generic: this is a version-1/CBC file, whose
         * decrypt path signals bad padding via a distinct status code
         * (MAKO_ERR_PADDING). Printing that code, or any other detail
         * that distinguishes *why* decryption failed, is exactly the
         * padding-oracle side channel this whole rewrite exists to
         * close (see docs/SECURITY.md and mode_cbc.c) -- so regardless
         * of which internal status came back, the CLI reports only
         * "decryption failed" here, identically to the version-2/GCM
         * failure path in do_decrypt() below. */
        fprintf(stderr, "Error: decryption failed, wrong passphrase or "
                         "corrupted file\n");
        free(plaintext);
        return 1;
    }

    int result = write_entire_file(output_path, plaintext, plaintext_len);
    free(plaintext);

    if (result != 0) {
        fprintf(stderr, "Error: could not write output file '%s'\n", output_path);
        return 1;
    }

    printf("Decrypted '%s' -> '%s' (%zu bytes, format v1/CBC -- legacy file)\n",
           input_path, output_path, plaintext_len);
    return 0;
}

/*
 * Decrypts a version-2 (GCM) file: the current, and only newly-written,
 * format.
 */
static int do_decrypt_v2(const uint8_t *file_data, size_t file_len,
                          const char *passphrase, const char *input_path,
                          const char *output_path) {
    if (file_len < MAKO_HEADER_V2_SIZE) {
        fprintf(stderr, "Error: decryption failed\n");
        return 1;
    }

    uint8_t key_size_flag = file_data[MAKO_MAGIC_LEN + 1];
    mako_key_size_t key_size = (key_size_flag == 0) ? MAKO_KEY_128 : MAKO_KEY_256;

    const uint8_t *salt = file_data + MAKO_MAGIC_LEN + 2;
    const uint8_t *nonce = salt + MAKO_KDF_SALT_SIZE;
    const uint8_t *header_bytes = file_data; /* first MAKO_HEADER_V2_FIELDS_SIZE bytes */
    const uint8_t *tag = file_data + MAKO_HEADER_V2_FIELDS_SIZE;
    const uint8_t *ciphertext = file_data + MAKO_HEADER_V2_SIZE;
    size_t ciphertext_len = file_len - MAKO_HEADER_V2_SIZE;

    uint8_t key[MAKO_KEY256_BYTES];
    size_t key_bytes = (key_size == MAKO_KEY_128) ? MAKO_KEY128_BYTES : MAKO_KEY256_BYTES;
    mako_kdf_derive((const uint8_t *)passphrase, strlen(passphrase), salt,
                     key, key_bytes);

    mako_key_schedule_t ks;
    if (mako_key_init(key, key_size, &ks) != MAKO_OK) {
        fprintf(stderr, "Error: decryption failed\n");
        return 1;
    }

    uint8_t *plaintext = malloc(ciphertext_len > 0 ? ciphertext_len : 1);
    if (plaintext == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        return 1;
    }

    mako_status_t status = mako_gcm_decrypt(&ks, ciphertext, ciphertext_len,
                                             nonce, header_bytes,
                                             MAKO_HEADER_V2_FIELDS_SIZE, tag,
                                             plaintext,
                                             ciphertext_len > 0 ? ciphertext_len : 1);

    if (status != MAKO_OK) {
        /* Generic on purpose: a bad passphrase, a bad key size, a
         * flipped ciphertext byte, a tampered header, and a truncated
         * file are all indistinguishable failures here
         * (MAKO_ERR_AUTH_FAILED), which is exactly the point -- see the
         * mako_gcm_decrypt() documentation in makocrypto.h. */
        fprintf(stderr, "Error: decryption failed, wrong passphrase or "
                         "corrupted file\n");
        free(plaintext);
        return 1;
    }

    int result = write_entire_file(output_path, plaintext, ciphertext_len);
    free(plaintext);

    if (result != 0) {
        fprintf(stderr, "Error: could not write output file '%s'\n", output_path);
        return 1;
    }

    printf("Decrypted '%s' -> '%s' (%zu bytes)\n",
           input_path, output_path, ciphertext_len);
    return 0;
}

static int do_decrypt(const char *input_path, const char *output_path,
                       const char *passphrase) {
    size_t file_len = 0;
    uint8_t *file_data = read_entire_file(input_path, &file_len);
    if (file_data == NULL) {
        fprintf(stderr, "Error: could not read input file '%s'\n", input_path);
        return 1;
    }

    /* The version byte lives at a fixed offset present in both header
     * layouts (magic, then version), so it can be inspected before
     * committing to either decode path. */
    if (file_len < MAKO_MAGIC_LEN + 1 ||
        memcmp(file_data, MAKO_MAGIC, MAKO_MAGIC_LEN) != 0) {
        fprintf(stderr, "Error: '%s' is not a valid Makocrypto file "
                         "(missing MAKOTA signature)\n", input_path);
        free(file_data);
        return 1;
    }

    uint8_t version = file_data[MAKO_MAGIC_LEN];
    int result;

    if (version == MAKO_FORMAT_VERSION_1) {
        result = do_decrypt_v1(file_data, file_len, passphrase, input_path,
                                output_path);
    } else if (version == MAKO_FORMAT_VERSION_2) {
        result = do_decrypt_v2(file_data, file_len, passphrase, input_path,
                                output_path);
    } else {
        fprintf(stderr, "Error: unrecognized Makocrypto format version (%d)\n",
                (int)version);
        result = 1;
    }

    free(file_data);
    return result;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *input_path = NULL;
    const char *output_path = NULL;
    const char *passphrase = NULL;
    int key_bits = 256;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            input_path = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            passphrase = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_bits = atoi(argv[++i]);
        } else {
            fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (input_path == NULL || output_path == NULL || passphrase == NULL) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(mode, "encrypt") == 0) {
        if (key_bits != 128 && key_bits != 256) {
            fprintf(stderr, "Error: -k must be 128 or 256\n");
            return 1;
        }
        mako_key_size_t key_size = (key_bits == 128) ? MAKO_KEY_128 : MAKO_KEY_256;
        return do_encrypt(input_path, output_path, passphrase, key_size);
    } else if (strcmp(mode, "decrypt") == 0) {
        return do_decrypt(input_path, output_path, passphrase);
    } else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        print_usage(argv[0]);
        return 1;
    }
}
