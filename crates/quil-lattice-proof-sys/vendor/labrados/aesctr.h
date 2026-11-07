#ifndef AESCTR_H
#define AESCTR_H

#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>

#define AES128CTR_NAMESPACE(s) aes128ctr_avx2_##s
#define AES256CTR_NAMESPACE(s) aes256ctr_avx2_##s

#define AES128CTR_BLOCKBYTES 512
#define AES256CTR_BLOCKBYTES 512

typedef struct {
  __m128i rkeys[11];
  __m128i n;
} aes128ctr_ctx;

typedef struct {
  __m128i rkeys[15];
  __m128i n;
} aes256ctr_ctx;

#define aes128ctr_init AES128CTR_NAMESPACE(init)
void aes128ctr_init(aes128ctr_ctx *state, const uint8_t key[16], uint64_t nonce);

#define aes128ctr_select AES128CTR_NAMESPACE(select)
void aes128ctr_select(aes128ctr_ctx *state, uint64_t nonce);

#define aes128ctr_squeezeblocks AES128CTR_NAMESPACE(squeezeblocks)
void aes128ctr_squeezeblocks(uint8_t *out, size_t nblocks, aes128ctr_ctx *state);

#define aes256ctr_init AES256CTR_NAMESPACE(init)
void aes256ctr_init(aes256ctr_ctx *state, const uint8_t key[32], uint64_t nonce);

#define aes256ctr_select AES256CTR_NAMESPACE(select)
void aes256ctr_select(aes256ctr_ctx *state, uint64_t nonce);

#define aes256ctr_squeezeblocks AES256CTR_NAMESPACE(squeezeblocks)
void aes256ctr_squeezeblocks(uint8_t *out, size_t nblocks, aes256ctr_ctx *state);

#endif
