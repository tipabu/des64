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

While it would be nice to be able to condense that, we don't know enough
about the cipher's inputs or key format to do so.
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

/* Read a block from a file descriptor. Returns 0 if there are more blocks to read,
   or 1 if there aren't. Final blocks will be padded as necessary. Per PKCS #5, the
   padding byte will be the number of bytes thus added (ie, 0x01 - 0x08).
   Note that there will always be at least one block with some padding; if the file
   is a multiple of the block size, the final block will be entirely padding.
 */
int read_block(uint64_t *b, FILE *f, uint8_t bs) {
  int8_t i;
  int c = 0;
  uint64_t p;
  for (*b = 0, i = bs; i-- && EOF != (c = fgetc(f));)
    *b |= ((uint64_t)c&0xff)<<(i<<3);
  p = i + 1; // # of bytes that we're adding
  while (i > -1) *b |= p << (i-- << 3);
  return c != EOF;
}
/* Write a block to a file descriptor. Returns 0 if the write was successful, or 1
   if there was an error. If flagged as the final decrypt block, remove the padding
   bytes (whose count is specified by the final byte) before writing.
   Note that if the plaintext was a multiple of the block size, the final decrypted
   block will be entirely padding, and this won't write anything.
 */
int write_block(uint64_t b, FILE *f, uint8_t bs, uint8_t final) {
  uint8_t i = bs;
  int r;
  if (final) {
    r = b & 0xff; // # of bytes that were added
    if (r <= bs) { // Let's do *some* sort of validation on the padding...
      i -= r;
      b >>= (r << 3);
    }
  }
  r = 0;
  while (!r && i--)
    r |= (EOF == fputc((b>>(i<<3)) & 0xff, f));
  return r;
}
