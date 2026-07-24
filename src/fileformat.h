#ifndef MAKOCRYPTO_FILEFORMAT_H
#define MAKOCRYPTO_FILEFORMAT_H

#include <stdint.h>

#include "makocrypto/makocrypto.h"

/*
 * Every file produced by the CLI starts with this 6-byte brand marker
 * ('M','A','K','O','T','A'). This is a plain file-signature, the same
 * mechanism used by formats like PNG or ZIP to identify their own files;
 * it lives entirely outside the encrypted payload and has no bearing on
 * the cipher's security, cryptanalytic resistance, or key secrecy. It
 * exists purely so tooling (and curious users opening the file in a text
 * editor) can recognize a Makocrypto container at a glance.
 */
#define MAKO_MAGIC "MAKOTA"
#define MAKO_MAGIC_LEN 6
#define MAKO_FORMAT_VERSION 1

typedef struct {
    char magic[MAKO_MAGIC_LEN];
    uint8_t version;
    uint8_t key_size_flag; /* 0 = 128-bit, 1 = 256-bit */
    uint8_t iv[MAKO_IV_SIZE];
} mako_file_header_t;

#define MAKO_HEADER_SIZE (MAKO_MAGIC_LEN + 1 + 1 + MAKO_IV_SIZE)

#endif /* MAKOCRYPTO_FILEFORMAT_H */
