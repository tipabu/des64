#include <stdio.h>
#include "crypto.h"

int main(int argc, char *argv[]){
  int i = 1;
  uint8_t l;
  uint64_t p, k, c, cc;
  FILE *f = stdin;
  do {
    if (argc > 1) {
      if (NULL == (f = fopen(argv[i], "r"))) {
        fprintf(stderr, "Error opening file: %s\n", argv[i]);
        return 1;
      } else
        fprintf(stderr, "Testing file: %s\n", argv[i]);
    }
    for (l = 1; fscanf(f, "%" SCNx64 " %" SCNx64 " %" SCNx64, &k, &p, &c) == 3; l++) {
      if (des(1, &p, &k, 0, &cc, CRYPT_ENCRYPT | DES1 | CRYPT_ECB)) {
        fprintf(stderr, "%3d: parity error in key\n", l);
        continue;
      }
      if (c != cc)
        fprintf(stderr, "%3d (e): calculated %016" PRIX64 ", expected %016" PRIX64 "\n", l, cc, c);
      if (des(1, &c, &k, 0, &cc, CRYPT_DECRYPT | DES1 | CRYPT_ECB)) {
        fprintf(stderr, "%3d: parity error in key\n", l);
        continue;
      }
      if (p != cc)
        fprintf(stderr, "%3d (d): calculated %016" PRIX64 ", expected %016" PRIX64 "\n", l, cc, p);
    }
    fclose(f);
  } while (++i < argc);
  return 0;
}
