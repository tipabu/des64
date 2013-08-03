#include <stdio.h>
#include "crypto.h"

#define swap(x, y) {x^=y;y^=x;x^=y;}

static const uint8_t
ip[64] = {
   6, 14, 22, 30, 38, 46, 54, 62,  4, 12, 20, 28, 36, 44, 52, 60,
   2, 10, 18, 26, 34, 42, 50, 58,  0,  8, 16, 24, 32, 40, 48, 56,
   7, 15, 23, 31, 39, 47, 55, 63,  5, 13, 21, 29, 37, 45, 53, 61,
   3, 11, 19, 27, 35, 43, 51, 59,  1,  9, 17, 25, 33, 41, 49, 57},
ipi[64] = {
  24, 56, 16, 48,  8, 40,  0, 32, 25, 57, 17, 49,  9, 41,  1, 33,
  26, 58, 18, 50, 10, 42,  2, 34, 27, 59, 19, 51, 11, 43,  3, 35,
  28, 60, 20, 52, 12, 44,  4, 36, 29, 61, 21, 53, 13, 45,  5, 37,
  30, 62, 22, 54, 14, 46,  6, 38, 31, 63, 23, 55, 15, 47,  7, 39},
e[48] = {
   0, 31, 30, 29, 28, 27, 28, 27, 26, 25, 24, 23,
  24, 23, 22, 21, 20, 19, 20, 19, 18, 17, 16, 15,
  16, 15, 14, 13, 12, 11, 12, 11, 10,  9,  8,  7,
   8,  7,  6,  5,  4,  3,  4,  3,  2,  1,  0, 31},
p[32] = {
  16, 25, 12, 11,  3, 20,  4, 15, 31, 17,  9,  6, 27, 14,  1, 22,
  30, 24,  8, 18,  0,  5, 29, 23, 13, 19,  2, 26, 10, 21, 28,  7},
pc1l[28] = {
   7, 15, 23, 31, 39, 47, 55, 63,  6, 14, 22, 30, 38, 46,
  54, 62,  5, 13, 21, 29, 37, 45, 53, 61,  4, 12, 20, 28},
pc1r[28] = {
   1,  9, 17, 25, 33, 41, 49, 57,  2, 10, 18, 26, 34, 42,
  50, 58,  3, 11, 19, 27, 35, 43, 51, 59, 36, 44, 52, 60},
pc2[48] = {
  42, 39, 45, 32, 55, 51, 53, 28, 41, 50, 35, 46,
  33, 37, 44, 52, 30, 48, 40, 49, 29, 36, 43, 54,
  15,  4, 25, 19,  9,  1, 26, 16,  5, 11, 23,  8,
  12,  7, 17,  0, 22,  3, 10, 14,  6, 20, 27, 24},
s_box[8][64] = {
  {14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
    3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
    4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
   15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13},
  {15,  3,  1, 13,  8,  4, 14,  7,  6, 15, 11,  2,  3,  8,  4, 14,
    9, 12,  7,  0,  2,  1, 13, 10, 12,  6,  0,  9,  5, 11, 10,  5,
    0, 13, 14,  8,  7, 10, 11,  1, 10,  3,  4, 15, 13,  4,  1,  2,
    5, 11,  8,  6, 12,  7,  6, 12,  9,  0,  3,  5,  2, 14, 15,  9},
  {10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
    1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
   13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
   11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12},
  { 7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
    1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
   10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
   15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14},
  { 2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
    8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
    4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
   15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3},
  {12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
    0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
    9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
    7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13},
  { 4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
    3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
    1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
   10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12},
  {13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
   10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
    7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
    0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11}
},
rot[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

#define get_bit(x,bit) ( ( (x) >> (bit) ) & 1 )
uint64_t reorder(uint64_t b, const uint8_t o[], uint8_t c) {
  uint8_t i;
  uint64_t r = 0;
  for (i = 0; i < c; i++) {
    r |= get_bit(b, o[i]) << (c-1-i);
  }
  return r;
}

uint32_t F(uint32_t block, uint48_t key) {
  uint8_t i;
  key ^= reorder(block, e, 48);
  for (block = i = 0; i < 8; i++) {
    block <<= 4;
    block |= s_box[i][(key >> (42-6*i)) & 0x3f];
  }
  block = reorder(block, p, 32);
  return block;
}

int validate_key(uint64_t key) {
  int i;
  const uint64_t t = 0x0101010101010101LLU;
  for (i = 0; i < 3; i++) key ^= key >> (1 << i);
  return (key & t) != t;
}
void gen_key(uint64_t key, uint48_t key_ring[DES_ROUNDS], uint8_t mode) {
  uint8_t i;
  uint32_t L, R;
  L = reorder(key, pc1l, 28);
  R = reorder(key, pc1r, 28);
  for (i = 0; i < DES_ROUNDS; i++) {
    L = ((L << rot[i]) | (L >> (28-rot[i]))) & 0x0fffffff;
    R = ((R << rot[i]) | (R >> (28-rot[i]))) & 0x0fffffff;
    if ((mode & CRYPT_MODE_MASK) == CRYPT_DECRYPT && ((mode & CRYPT_BLOCK_MASK) == CRYPT_ECB || (mode & CRYPT_BLOCK_MASK) == CRYPT_CBC))
      key_ring[DES_ROUNDS-1-i] = reorder( ((uint64_t)L << 28) | R, pc2, 48 );
    else
      key_ring[i] = reorder( ((uint64_t)L << 28) | R, pc2, 48 );
  }
}

void gen_key_ring(uint64_t key[], des_key_ring ring, uint8_t mode) {
  switch (mode & DES_MASK) {
    case DES7:
      gen_key(key[3], ring[3], mode ^ CRYPT_MODE_MASK);
    case DES5:
      gen_key(key[2], ring[2], mode);
    case DES3:
      gen_key(key[1], ring[1], mode ^ CRYPT_MODE_MASK);
    case DES1:
      gen_key(key[0], ring[0], mode);
  }
}

uint64_t des_block(uint64_t block, uint48_t k[DES_ROUNDS]) {
  uint32_t L, R;
  uint8_t i;
  block = reorder(block, ip, 64);
  L = (block >> 32) & 0xffffffff;
  R = block & 0xffffffff;
  for (i = 0; i < DES_ROUNDS; i+=2) {
    L ^= F(R, k[i]);
    R ^= F(L, k[i+1]);
  }
  block = ((uint64_t)R << 32) | L;
  block = reorder(block, ipi, 64);
  return block;
}
uint64_t des3_block(uint64_t block, des_key_ring key_ring) {
  return des_block(des_block(des_block(block, key_ring[0]), key_ring[1]), key_ring[0]);
}
uint64_t des5_block(uint64_t block, des_key_ring key_ring) {
  return des_block(des_block(des_block(des_block(des_block(block, key_ring[0]), key_ring[1]), key_ring[2]), key_ring[1]), key_ring[0]);
}
uint64_t des7_block(uint64_t block, des_key_ring key_ring) {
  return des_block(des_block(des_block(des_block(des_block(des_block(des_block(block, key_ring[0]), key_ring[1]), key_ring[2]), key_ring[3]), key_ring[2]), key_ring[1]), key_ring[0]);
}

int init_des_stream(uint64_t key[], uint64_t iv, uint8_t mode, des_key_ring k, struct block_cipher *bc) {
#ifndef DISABLE_PARITY_CHECK
  switch (mode & DES_MASK) {
    case DES7: if (validate_key(key[3])) return 1;
    case DES5: if (validate_key(key[2])) return 1;
    case DES3: if (validate_key(key[1])) return 1;
    case DES1: if (validate_key(key[0])) return 1;
  }
#endif
  bc->mode = mode;
  bc->iv = iv;
  bc->block_size = 8;
  gen_key_ring(key, k, mode);
  return 0;
}

uint64_t des_stream(uint64_t in, des_key_ring k, struct block_cipher *bc) {
  bc->in = in;
  switch (bc->mode & DES_MASK) {
    case DES1:
      bc->out = des_block(block_cipher_pre(bc), k[0]);
      break;
    case DES3:
      bc->out = des3_block(block_cipher_pre(bc), k);
      break;
    case DES5:
      bc->out = des5_block(block_cipher_pre(bc), k);
      break;
    case DES7:
      bc->out = des7_block(block_cipher_pre(bc), k);
      break;
  }
  return block_cipher_post(bc);
}

int des(uint64_t count, const uint64_t in[], uint64_t key[], uint64_t iv, uint64_t out[], uint8_t mode) {
  uint64_t i;
  des_key_ring k;
  struct block_cipher bc;
  if (init_des_stream(key, iv, mode, k, &bc)) return 1;
  for (i = 0; i < count; i++)
    out[i] = des_stream(in[i], k, &bc);
  return 0;
}
int des_file(FILE *i, uint64_t key[], uint64_t iv, FILE *o, uint8_t mode) {
  uint64_t b, lb = 0;
  des_key_ring k;
  struct block_cipher bc;
  if (init_des_stream(key, iv, mode, k, &bc)) {
    fprintf(stderr, "Error initializing DES key ring.\n");
    return 1;
  }
  if (read_block(&b, i, bc.block_size)) {
    lb = b;
    while (read_block(&b, i, bc.block_size)) {
      if (write_block(des_stream(lb, k, &bc), o, bc.block_size, 0)) {
        fprintf(stderr, "Error writing block.\n");
        return 1;
      }
      lb = b;
    }
    if ((bc.mode & CRYPT_MODE_MASK) == CRYPT_ENCRYPT) {
      if (write_block(des_stream(lb, k, &bc), o, bc.block_size, 0)) {
        fprintf(stderr, "Error writing block.\n");
        return 1;
      }
      lb = b;
    }
  }
  if (write_block(des_stream(lb, k, &bc), o, bc.block_size, (bc.mode & CRYPT_MODE_MASK) == CRYPT_DECRYPT)) {
    fprintf(stderr, "Error writing block.\n");
    return 1;
  }
  return 0;
}
