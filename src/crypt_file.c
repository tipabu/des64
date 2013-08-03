#include "crypto.h"
int main() {
  uint64_t k[] = {0x0123456789abcdefLLU, 0x0416198512021985LLU};
  uint8_t m = DES3 | CRYPT_CBC;
  #ifdef ENCRYPT
    m |= CRYPT_ENCRYPT;
  #else
    m |= CRYPT_DECRYPT;
  #endif
  return des_file(stdin, k, 0, stdout, m);
}
