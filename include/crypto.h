#include <inttypes.h>
#include <stdio.h>

#define CRYPT_MODE_MASK  0x80
#define CRYPT_ENCRYPT 0x00
#define CRYPT_DECRYPT 0x80

#define CRYPT_BLOCK_MASK 0x0f
#define CRYPT_ECB  0x00
#define CRYPT_CBC  0x01
#define CRYPT_OFB  0x02
#define CRYPT_CFB  0x03
#define CRYPT_CTR  0x04
/*
#define CRYPT_IAPM 0x05
#define CRYPT_CCM  0x06
#define CRYPT_EAX  0x07
#define CRYPT_GCM  0x08
#define CRYPT_OCB  0x09
#define CRYPT_LWR  0x0a
#define CRYPT_CMC  0x0b
#define CRYPT_EME  0x0c
*/

// block size is measured in bytes, not bits.
struct block_cipher {
  uint8_t mode, block_size;
  uint64_t in, out, iv;
};

int read_block(uint64_t *b, FILE *f, uint8_t bs);
int write_block(uint64_t b, FILE *f, uint8_t bs, uint8_t final);
uint64_t block_cipher_pre(struct block_cipher *bc);
uint64_t block_cipher_post(struct block_cipher *bc);

#include "des.h"
