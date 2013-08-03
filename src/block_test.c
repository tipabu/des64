#include <stdio.h>
#include <string.h>
#include "crypto.h"

#define KEYS 2
#define BUF_LEN 8

int main() {
  uint8_t i;
  uint64_t d[BUF_LEN], r[BUF_LEN],
           s[BUF_LEN] = {0x54686520756e6b6eLLU, 0x6f776e206d657373LLU,
                         0x6167652069733a20LLU, 0x546865204445532dLLU,
                         0x7465737420636f6eLLU, 0x7465737427732070LLU,
                         0x6c61696e74657874LLU, 0x0808080808080808LLU},
           k[KEYS] =    {0x5ed9204fece0b967LLU, 0x7329751086434538LLU},
           iv =          0xa2185abf459660bfLLU;
  struct { char *s; uint8_t m; }
  tests[] = {
    {"Electronic Codebook (ECB)", CRYPT_ECB},
    {"Cipher Block Chaining (CBC)", CRYPT_CBC},
    {"Output Feedback (OFB)", CRYPT_OFB},
    {"Cipher Feedback (CFB)", CRYPT_CFB},
    {"Counter (CTR)", CRYPT_CTR}
  };
  for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
    if (des(BUF_LEN, s, k, iv, r, CRYPT_ENCRYPT | DES3 | tests[i].m))
      fprintf(stderr, "Parity error during encryption.\n");
    if (des(BUF_LEN, r, k, iv, d, CRYPT_DECRYPT | DES3 | tests[i].m))
      fprintf(stderr, "Parity error during decryption.\n");
    if (memcmp(d, s, BUF_LEN*sizeof(uint64_t)) == 0)
      printf("%35s: PASS\n", tests[i].s);
    else
      printf("%35s: FAIL\n", tests[i].s);
  }
  return 0;
}
