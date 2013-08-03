#define DES_ROUNDS 16

typedef uint64_t uint48_t;
typedef uint48_t des_key_ring[4][DES_ROUNDS];

#define DES_MASK 0x30
#define DES1 0x00
#define DES3 0x10
#define DES5 0x20
#define DES7 0x30

uint64_t des_block(uint64_t block, const uint64_t k[DES_ROUNDS]);
uint64_t des3_block(uint64_t block, des_key_ring k);
uint64_t des5_block(uint64_t block, des_key_ring k);
uint64_t des7_block(uint64_t block, des_key_ring k);

int validate_key(uint64_t key);
void gen_key_ring(uint64_t key[], des_key_ring ring, uint8_t mode);

int init_des_stream(uint64_t key[], uint64_t initialization_vector, uint8_t mode, des_key_ring k, struct block_cipher *bc);
uint64_t des_stream(uint64_t input, des_key_ring k, struct block_cipher *bc);

int des(uint64_t buffer_length, const uint64_t input_buffer[], uint64_t key[], uint64_t initialization_vector, uint64_t output_buffer[], uint8_t mode);
int des_file(FILE *input, uint64_t key[], uint64_t initialization_vector, FILE *output, uint8_t mode);
