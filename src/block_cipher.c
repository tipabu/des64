#include <stdio.h>
#include "crypto.h"

/*
You should be able to do something like:

  struct block_cipher bc;
  bc.mode = ...
  bc.iv = ...

  bc.in = *input++;
  bc.out = cipher(block_cipher_pre(&bc), key);
  *output++ = block_cipher_post(&bc);

  bc.in = *input++;
  bc.out = cipher(block_cipher_pre(&bc), key);
  *output++ = block_cipher_post(&bc);

  ...

*/

// Generate input to the cipher
uint64_t block_cipher_pre(struct block_cipher *bc) {
  switch (bc->mode & CRYPT_BLOCK_MASK) {
    case CRYPT_ECB:
      return bc->in;
    case CRYPT_CBC:
      if ((bc->mode & CRYPT_MODE_MASK) == CRYPT_ENCRYPT)
        return bc->iv ^ bc->in;
      else
        return (bc->iv ^= bc->in, bc->in ^= bc->iv, bc->iv ^= bc->in);
      break;
    case CRYPT_CFB:
    case CRYPT_OFB:
      return bc->iv;
      break;
    case CRYPT_CTR:
      return bc->iv++;
      break;
    default:
      return 0;
  }
}

// Generate ciphertext after performing the cipher
uint64_t block_cipher_post(struct block_cipher *bc) {
  switch (bc->mode & CRYPT_BLOCK_MASK) {
    case CRYPT_ECB:
      return bc->out;
    case CRYPT_CBC:
      if ((bc->mode & CRYPT_MODE_MASK) == CRYPT_ENCRYPT)
        return bc->iv = bc->out;
      else
        return bc->in ^ bc->out;
      break;
    case CRYPT_CFB:
      if ((bc->mode & CRYPT_MODE_MASK) == CRYPT_ENCRYPT)
        return bc->iv = bc->in ^ bc->out;
      else
        return bc->out ^ (bc->iv = bc->in);
      break;
    case CRYPT_OFB:
      return bc->in ^ (bc->iv = bc->out);
      break;
    case CRYPT_CTR:
      return bc->in ^ bc->out;
      break;
    default:
      return 0;
  }
}

int read_block(uint64_t *b, FILE *f, uint8_t bs) {
  int8_t i;
  int c = 0;
  for (*b = 0, i = bs; i-- && EOF != (c = fgetc(f));)
    *b |= ((uint64_t)c&0xff)<<(i<<3);
  if (i > -1) *b |= (uint64_t)0x80<<(i<<3);
  return c != EOF;
}
int write_block(uint64_t b, FILE *f, uint8_t bs, uint8_t final) {
  uint8_t i = bs;
  int r = 0;
  if (final) {
    while (i && (b & 0xff) != 0x80) {
      i--, b >>= 8;
    }
    i--, b >>= 8;
  }
  while (!r && i--)
    r |= (EOF == fputc((b>>(i<<3)) & 0xff, f));
  return r;
}

