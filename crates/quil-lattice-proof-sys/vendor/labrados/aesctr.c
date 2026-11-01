/* Based heavily on public-domain code by Romain Dolbeau
 * Different handling of nonce+counter than original version using
 * separated 64-bit nonce and internal 64-bit counter, starting from zero
 * Public Domain */

#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include "aesctr.h"

static inline void vaesni_encrypt8(uint8_t out[512], __m128i *n, const __m128i *rkeys, int rounds)
{
  int i;
  __m512i f0,f1,f2,f3,f4,f5,f6,f7,k;
  const __m512i off0 = _mm512_set_epi64(3,0,2,0,1,0,0,0);
  const __m512i off1 = _mm512_broadcast_i64x2(_mm_set_epi64x(4,0));
  const __m512i off2 = _mm512_broadcast_i64x2(_mm_set_epi64x(8,0));
  const __m512i off3 = _mm512_broadcast_i64x2(_mm_set_epi64x(12,0));

  /* Increase counter in 8 consecutive blocks */
  f0 = _mm512_broadcast_i32x4(_mm_load_si128(n));
  f0 = _mm512_add_epi64(f0,off0);
  f1 = _mm512_add_epi64(f0,off1);
  f2 = _mm512_add_epi64(f0,off2);
  f3 = _mm512_add_epi64(f0,off3);
  f4 = _mm512_add_epi64(f1,off3);
  f5 = _mm512_add_epi64(f2,off3);
  f6 = _mm512_add_epi64(f3,off3);
  f7 = _mm512_add_epi64(f4,off3);

  /* Write counter for next iteration, increased by 32 */
  _mm_store_si128(n,_mm_add_epi64(_mm512_castsi512_si128(f5),_mm512_castsi512_si128(off3)));

  /* Actual AES encryption, 5x interleaved */
  k  = _mm512_broadcast_i32x4(_mm_load_si128(rkeys));
  f0 = _mm512_xor_si512(f0,k);
  f1 = _mm512_xor_si512(f1,k);
  f2 = _mm512_xor_si512(f2,k);
  f3 = _mm512_xor_si512(f3,k);
  f4 = _mm512_xor_si512(f4,k);
  f5 = _mm512_xor_si512(f5,k);
  f6 = _mm512_xor_si512(f6,k);
  f7 = _mm512_xor_si512(f7,k);

  for(i=1;i<rounds;i++) {
    k  = _mm512_broadcast_i32x4(_mm_load_si128(rkeys+i));
    f0 = _mm512_aesenc_epi128(f0,k);
    f1 = _mm512_aesenc_epi128(f1,k);
    f2 = _mm512_aesenc_epi128(f2,k);
    f3 = _mm512_aesenc_epi128(f3,k);
    f4 = _mm512_aesenc_epi128(f4,k);
    f5 = _mm512_aesenc_epi128(f5,k);
    f6 = _mm512_aesenc_epi128(f6,k);
    f7 = _mm512_aesenc_epi128(f7,k);
  }

  k  = _mm512_broadcast_i64x2(_mm_load_si128(rkeys+rounds));
  f0 = _mm512_aesenclast_epi128(f0,k);
  f1 = _mm512_aesenclast_epi128(f1,k);
  f2 = _mm512_aesenclast_epi128(f2,k);
  f3 = _mm512_aesenclast_epi128(f3,k);
  f4 = _mm512_aesenclast_epi128(f4,k);
  f5 = _mm512_aesenclast_epi128(f5,k);
  f6 = _mm512_aesenclast_epi128(f6,k);
  f7 = _mm512_aesenclast_epi128(f7,k);

  /* Write results */
  _mm512_storeu_si512((__m512i*)(out+  0),f0);
  _mm512_storeu_si512((__m512i*)(out+ 64),f1);
  _mm512_storeu_si512((__m512i*)(out+128),f2);
  _mm512_storeu_si512((__m512i*)(out+192),f3);
  _mm512_storeu_si512((__m512i*)(out+256),f4);
  _mm512_storeu_si512((__m512i*)(out+320),f5);
  _mm512_storeu_si512((__m512i*)(out+384),f6);
  _mm512_storeu_si512((__m512i*)(out+448),f7);
}

void aes128ctr_init(aes128ctr_ctx *state, const uint8_t key[16], uint64_t nonce)
{
  __m128i temp0, temp1, temp2;
  const __m128i zero = _mm_setzero_si128();
  int idx = 0;

  _mm_store_si128(&state->n,_mm_loadl_epi64((__m128i *)&nonce));

#define BLOCK1(IMM)                                                     \
  temp1 = _mm_aeskeygenassist_si128(temp0, IMM);                        \
  temp2 = (__m128i)_mm_shuffle_ps((__m128)zero, (__m128)temp0, 0x10);   \
  temp0 = _mm_xor_si128(temp0, temp2);                                  \
  temp2 = (__m128i)_mm_shuffle_ps((__m128)temp2, (__m128)temp0, 0x8c);  \
  temp0 = _mm_xor_si128(temp0, temp2);                                  \
  temp1 = (__m128i)_mm_shuffle_ps((__m128)temp1, (__m128)temp1, 0xff);  \
  temp0 = _mm_xor_si128(temp0, temp1)

  temp0 = _mm_loadu_si128((__m128i *)key);
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x01);
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x02);
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x04);
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x08);
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x10);
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x20);
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x40);
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x80);
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x1b);
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x36);
  _mm_store_si128(&state->rkeys[idx++],temp0);

#undef BLOCK1
}

void aes256ctr_init(aes256ctr_ctx *state, const uint8_t key[32], uint64_t nonce)
{
  __m128i key0, key1, temp0, temp1, temp2, temp4;
  int idx = 0;

  key0 = _mm_loadu_si128((__m128i *)(key+ 0));
  key1 = _mm_loadu_si128((__m128i *)(key+16));
  _mm_store_si128(&state->n,_mm_loadl_epi64((__m128i *)&nonce));

#define BLOCK1(IMM)                                                     \
  temp1 = _mm_aeskeygenassist_si128(temp2, IMM);                        \
  _mm_store_si128(&state->rkeys[idx++],temp2);                          \
  temp4 = (__m128i)_mm_shuffle_ps((__m128)temp4, (__m128)temp0, 0x10);  \
  temp0 = _mm_xor_si128(temp0, temp4);                                  \
  temp4 = (__m128i)_mm_shuffle_ps((__m128)temp4, (__m128)temp0, 0x8c);  \
  temp0 = _mm_xor_si128(temp0, temp4);                                  \
  temp1 = (__m128i)_mm_shuffle_ps((__m128)temp1, (__m128)temp1, 0xff);  \
  temp0 = _mm_xor_si128(temp0, temp1)

#define BLOCK2(IMM)                                                     \
  temp1 = _mm_aeskeygenassist_si128(temp0, IMM);                        \
  _mm_store_si128(&state->rkeys[idx++],temp0);                          \
  temp4 = (__m128i)_mm_shuffle_ps((__m128)temp4, (__m128)temp2, 0x10);  \
  temp2 = _mm_xor_si128(temp2, temp4);                                  \
  temp4 = (__m128i)_mm_shuffle_ps((__m128)temp4, (__m128)temp2, 0x8c);  \
  temp2 = _mm_xor_si128(temp2, temp4);                                  \
  temp1 = (__m128i)_mm_shuffle_ps((__m128)temp1, (__m128)temp1, 0xaa);  \
  temp2 = _mm_xor_si128(temp2, temp1)

  temp0 = key0;
  temp2 = key1;
  temp4 = _mm_setzero_si128();
  _mm_store_si128(&state->rkeys[idx++],temp0);
  BLOCK1(0x01);
  BLOCK2(0x01);

  BLOCK1(0x02);
  BLOCK2(0x02);

  BLOCK1(0x04);
  BLOCK2(0x04);

  BLOCK1(0x08);
  BLOCK2(0x08);

  BLOCK1(0x10);
  BLOCK2(0x10);

  BLOCK1(0x20);
  BLOCK2(0x20);

  BLOCK1(0x40);
  _mm_store_si128(&state->rkeys[idx++],temp0);

#undef BLOCK1
}

void aes128ctr_select(aes128ctr_ctx *state, uint64_t nonce) {
  _mm_store_si128(&state->n,_mm_loadl_epi64((__m128i *)&nonce));
}

void aes256ctr_select(aes256ctr_ctx *state, uint64_t nonce) {
  _mm_store_si128(&state->n,_mm_loadl_epi64((__m128i *)&nonce));
}

void aes128ctr_squeezeblocks(uint8_t *out, size_t nblocks, aes128ctr_ctx *state)
{
  size_t i;
  for(i=0;i<nblocks;i++) {
    vaesni_encrypt8(out, &state->n, state->rkeys, 10);
    out += AES128CTR_BLOCKBYTES;
  }
}

void aes256ctr_squeezeblocks(uint8_t *out, size_t nblocks, aes256ctr_ctx *state)
{
  size_t i;
  for(i=0;i<nblocks;i++) {
    vaesni_encrypt8(out, &state->n, state->rkeys, 14);
    out += AES256CTR_BLOCKBYTES;
  }
}
