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
        "  -k <128|256>     Key size in bits for encryption (default: 256)\n\n"
        "Every Makocrypto container begins with the ASCII marker \"MAKOTA\",\n"
        "so encrypted files can be identified by tools or a hex viewer.\n",
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

static int do_encrypt(const char *input_path, const char *output_path,
                       const char *passphrase, mako_key_size_t key_size) {
    size_t plaintext_len = 0;
    uint8_t *plaintext = read_entire_file(input_path, &plaintext_len);
    if (plaintext == NULL) {
        fprintf(stderr, "Error: could not read input file '%s'\n", input_path);
        return 1;
    }

    uint8_t key[MAKO_KEY256_BYTES];
    size_t key_bytes = (key_size == MAKO_KEY_128) ? MAKO_KEY128_BYTES : MAKO_KEY256_BYTES;
    mako_kdf_derive((const uint8_t *)passphrase, strlen(passphrase), key, key_bytes);

    mako_key_schedule_t ks;
    if (mako_key_init(key, key_size, &ks) != MAKO_OK) {
        fprintf(stderr, "Error: key initialization failed\n");
        free(plaintext);
        return 1;
    }

    mako_file_header_t header;
    memcpy(header.magic, MAKO_MAGIC, MAKO_MAGIC_LEN);
    header.version = MAKO_FORMAT_VERSION;
    header.key_size_flag = (key_size == MAKO_KEY_128) ? 0 : 1;

    if (mako_generate_iv(header.iv) != MAKO_OK) {
        fprintf(stderr, "Error: failed to generate a secure IV\n");
        free(plaintext);
        return 1;
    }

    size_t ciphertext_len = mako_cbc_encrypted_size(plaintext_len);
    uint8_t *ciphertext = malloc(ciphertext_len);
    if (ciphertext == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        free(plaintext);
        return 1;
    }

    size_t written_len = 0;
    mako_status_t status = mako_cbc_encrypt(&ks, plaintext, plaintext_len,
                                             header.iv, ciphertext,
                                             ciphertext_len, &written_len);
    free(plaintext);

    if (status != MAKO_OK) {
        fprintf(stderr, "Error: encryption failed (code %d)\n", status);
        free(ciphertext);
        return 1;
    }

    size_t total_len = MAKO_HEADER_SIZE + written_len;
    uint8_t *out_buf = malloc(total_len);
    if (out_buf == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        free(ciphertext);
        return 1;
    }

    memcpy(out_buf, header.magic, MAKO_MAGIC_LEN);
    out_buf[MAKO_MAGIC_LEN] = header.version;
    out_buf[MAKO_MAGIC_LEN + 1] = header.key_size_flag;
    memcpy(out_buf + MAKO_MAGIC_LEN + 2, header.iv, MAKO_IV_SIZE);
    memcpy(out_buf + MAKO_HEADER_SIZE, ciphertext, written_len);
    free(ciphertext);

    int result = write_entire_file(output_path, out_buf, total_len);
    free(out_buf);

    if (result != 0) {
        fprintf(stderr, "Error: could not write output file '%s'\n", output_path);
        return 1;
    }

    printf("Encrypted '%s' -> '%s' (%zu bytes, %d-bit key)\n",
           input_path, output_path, total_len, (int)key_size);
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

    if (file_len < MAKO_HEADER_SIZE ||
        memcmp(file_data, MAKO_MAGIC, MAKO_MAGIC_LEN) != 0) {
        fprintf(stderr, "Error: '%s' is not a valid Makocrypto file "
                         "(missing MAKOTA signature)\n", input_path);
        free(file_data);
        return 1;
    }

    uint8_t key_size_flag = file_data[MAKO_MAGIC_LEN + 1];
    mako_key_size_t key_size = (key_size_flag == 0) ? MAKO_KEY_128 : MAKO_KEY_256;

    uint8_t iv[MAKO_IV_SIZE];
    memcpy(iv, file_data + MAKO_MAGIC_LEN + 2, MAKO_IV_SIZE);

    const uint8_t *ciphertext = file_data + MAKO_HEADER_SIZE;
    size_t ciphertext_len = file_len - MAKO_HEADER_SIZE;

    uint8_t key[MAKO_KEY256_BYTES];
    size_t key_bytes = (key_size == MAKO_KEY_128) ? MAKO_KEY128_BYTES : MAKO_KEY256_BYTES;
    mako_kdf_derive((const uint8_t *)passphrase, strlen(passphrase), key, key_bytes);

    mako_key_schedule_t ks;
    if (mako_key_init(key, key_size, &ks) != MAKO_OK) {
        fprintf(stderr, "Error: key initialization failed\n");
        free(file_data);
        return 1;
    }

    uint8_t *plaintext = malloc(ciphertext_len);
    if (plaintext == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        free(file_data);
        return 1;
    }

    size_t plaintext_len = 0;
    mako_status_t status = mako_cbc_decrypt(&ks, ciphertext, ciphertext_len,
                                             iv, plaintext, ciphertext_len,
                                             &plaintext_len);
    free(file_data);

    if (status != MAKO_OK) {
        fprintf(stderr, "Error: decryption failed, wrong passphrase or "
                         "corrupted file (code %d)\n", status);
        free(plaintext);
        return 1;
    }

    int result = write_entire_file(output_path, plaintext, plaintext_len);
    free(plaintext);

    if (result != 0) {
        fprintf(stderr, "Error: could not write output file '%s'\n", output_path);
        return 1;
    }

    printf("Decrypted '%s' -> '%s' (%zu bytes)\n",
           input_path, output_path, plaintext_len);
    return 0;
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
