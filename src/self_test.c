#include <stdio.h>
#include <string.h>
#include "crypto.h"

#define BUF_LEN 8
#define PLAINTEXT {0x54686520756e6b6eLLU, 0x6f776e206d657373LLU, \
                   0x6167652069733a20LLU, 0x546865204445532dLLU, \
                   0x7465737420636f6eLLU, 0x7465737427732070LLU, \
                   0x6c61696e74657874LLU, 0x0808080808080808LLU}

// From http://people.csail.mit.edu/rivest/Destest.txt
int test_des() {
  uint64_t p = 0x9474b8e8c73bca7dLLU, q;
  int i;
  for (i=0;  i<8; i++) {
    des(1, &p, &p, 0, &q, CRYPT_ECB | DES1 | CRYPT_ENCRYPT);
    printf("%016" PRIX64 "\n", q);
    des(1, &q, &q, 0, &p, CRYPT_ECB | DES1 | CRYPT_DECRYPT);
    printf("%016" PRIX64 "\n", p);
  }
  return p != 0x1b1a2ddb4c642438LLU;
}

// From http://www.rsa.com/rsalabs/node.asp?id=2105
int test_des_cbc() {
  uint64_t c[BUF_LEN] = {0x3ea786f91d76bbd3LLU, 0x66c63f54eb3fe33fLLU,
                         0x3988814c8ba197f7LLU, 0xbe1bdd7efb399631LLU,
                         0x3c3d3b65c8b83e31LLU, 0x89f90414fbcdc370LLU,
                         0xc111a52f3aef80f4LLU, 0xcff543a4b1655baeLLU},
           p[BUF_LEN] = PLAINTEXT, cc[BUF_LEN],
           k  = 0x5ed9204fece0b967LLU,
           iv = 0xa2185abf459660bfLLU;
  if (des(BUF_LEN, p, &k, iv, cc, CRYPT_ENCRYPT | CRYPT_CBC | DES1))
    fprintf(stderr, "Parity error during encryption.\n");
  return memcmp(c, cc, BUF_LEN*sizeof(uint64_t));
}

int test_block_cipher(uint8_t mode) {
  uint8_t i;
  uint64_t c[BUF_LEN], cp[BUF_LEN], p[BUF_LEN] = PLAINTEXT;
  struct block_cipher bc;
  bc.mode = (mode & CRYPT_BLOCK_MASK) | CRYPT_ENCRYPT;
  bc.iv = 0;
  for (i = 0; i < BUF_LEN; i++) {
    bc.in = p[i];
    bc.out = block_cipher_pre(&bc);
    c[i] = block_cipher_post(&bc);
  }
  bc.mode = (mode & CRYPT_BLOCK_MASK) | CRYPT_DECRYPT;
  bc.iv = 0;
  for (i = 0; i < BUF_LEN; i++) {
    bc.in = c[i];
    bc.out = block_cipher_pre(&bc);
    cp[i] = block_cipher_post(&bc);
  }
  return memcmp(p, cp, BUF_LEN*sizeof(uint64_t));
}

int test_ecb() { return test_block_cipher(CRYPT_ECB); }
int test_cbc() { return test_block_cipher(CRYPT_CBC); }
int test_cfb() { return test_block_cipher(CRYPT_CFB); }
int test_ofb() { return test_block_cipher(CRYPT_OFB); }
int test_ctr() { return test_block_cipher(CRYPT_CTR); }

int test_desn(uint8_t mode) {
  uint64_t d[BUF_LEN], r[BUF_LEN],
           s[BUF_LEN] = PLAINTEXT,
           k[] = {0x5ed9204fece0b967LLU, 0x7329751086434538LLU,
                  0x2634980423799125LLU, 0x8623469251433479LLU},
           iv =   0xa2185abf459660bfLLU;
  if (des(BUF_LEN, s, k, iv, r, CRYPT_ENCRYPT | CRYPT_ECB | (mode & DES_MASK)))
    fprintf(stderr, "Parity error during encryption.\n");
  if (des(BUF_LEN, r, k, iv, d, CRYPT_DECRYPT | CRYPT_ECB | (mode & DES_MASK)))
    fprintf(stderr, "Parity error during decryption.\n");
  return memcmp(d, s, BUF_LEN*sizeof(uint64_t));
}
int test_des1() { return test_desn(DES1); }
int test_des3() { return test_desn(DES3); }
int test_des5() { return test_desn(DES5); }
int test_des7() { return test_desn(DES7); }

//#define SHORT

int main() {
  int i, r = 0;
  struct { char *name; char *abbrev; int (*func)(); }
  tests[] = {
    {"Data Encryption Standard Self Test", "DES-ST", test_des},
    {"Data Encryption Standard CBC Test", "DES-CBC", test_des_cbc},
    {"Data Encryption Standard: Single", "DES1", test_des1},
    {"Data Encryption Standard: Triple", "DES3", test_des3},
    {"Data Encryption Standard: Quintuple", "DES5", test_des5},
    {"Data Encryption Standard: Septuple", "DES7", test_des7},
    {"Block Mode: Electronic Codebook", "ECB", test_ecb},
    {"Block Mode: Cipher Block Chaining", "CBC", test_cbc},
    {"Block Mode: Output Feedback", "OFB", test_ofb},
    {"Block Mode: Cipher Feedback", "CFB", test_cfb},
    {"Block Mode: Counter", "CTR", test_ctr}
  };
  for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++)
#ifdef SHORT
    if (tests[i].func())
      fprintf(stderr, "%10s: FAIL\n", tests[i].abbrev), r = 1;
    else
      fprintf(stderr, "%10s: PASS\n", tests[i].abbrev);
#else
    if (tests[i].func())
      fprintf(stderr, "%-40s FAIL\n", tests[i].name), r = 1;
    else
      fprintf(stderr, "%-40s PASS\n", tests[i].name);
#endif
  return r;
}
