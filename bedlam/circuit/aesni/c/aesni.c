/*
 * Circuit garbling using AES-NI instructions.
 */

#include <wmmintrin.h>
#include <emmintrin.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#define AES_BLOCK_SIZE 16

struct cipher
{
  __m128i key[15];
};

typedef struct cipher cipher;

struct label
{
  uint64_t d0;
  uint64_t d1;
};

typedef struct label label;

static inline void
label_xor(label *l, label *o)
{
  l->d0 ^= o->d0;
  l->d1 ^= o->d1;
}

static inline void
label_mul2(label *l)
{
  l->d0 <<= 1;
  l->d0 |= (l->d1 >> 63);
  l->d1 <<= 1;
}

static inline void
label_mul4(label *l)
{
  l->d0 <<= 2;
  l->d0 |= (l->d1 >> 62);
  l->d1 <<= 2;
}

static inline label *
make_k(label *a, label *b, uint32_t t)
{
  label tweak = {(uint64_t) t, 0};

  label_mul2(a);
  label_mul4(b);
  label_xor(a, b);
  label_xor(a, &tweak);

  return a;
}

void
garble2(cipher *cipher, label *a, label *b, label *c, uint32_t t, label *ret)
{
  label *label_k;
  __m128i k;
  __m128i pi;

  label_k = make_k(a, b, t);
  k = _mm_set_epi64x(label_k->d0, label_k->d1);

  /* Perform the AES encryption rounds. */
  pi = _mm_xor_si128(k, cipher->key[0]);
  pi = _mm_aesenc_si128(pi, cipher->key[1]);
  pi = _mm_aesenc_si128(pi, cipher->key[2]);
  pi = _mm_aesenc_si128(pi, cipher->key[3]);
  pi = _mm_aesenc_si128(pi, cipher->key[4]);
  pi = _mm_aesenc_si128(pi, cipher->key[5]);
  pi = _mm_aesenc_si128(pi, cipher->key[6]);
  pi = _mm_aesenc_si128(pi, cipher->key[7]);
  pi = _mm_aesenc_si128(pi, cipher->key[8]);
  pi = _mm_aesenc_si128(pi, cipher->key[9]);
  pi = _mm_aesenc_si128(pi, cipher->key[10]);
  pi = _mm_aesenc_si128(pi, cipher->key[11]);
  pi = _mm_aesenc_si128(pi, cipher->key[12]);
  pi = _mm_aesenc_si128(pi, cipher->key[13]);
  pi = _mm_aesenclast_si128(pi, cipher->key[14]);

  ret->d0 = ((uint64_t *) &pi)[0];
  ret->d1 = ((uint64_t *) &pi)[1];

  label_xor(ret, label_k);
  label_xor(ret, c);
}

void
make_cipher(cipher *cipher, const unsigned char key[AES_BLOCK_SIZE])
{
  cipher->key[0] = _mm_loadu_si128((__m128i *)key);
  cipher->key[1] = _mm_aeskeygenassist_si128(cipher->key[0], 0x01);
  cipher->key[2] = _mm_aeskeygenassist_si128(cipher->key[1], 0x02);
  cipher->key[3] = _mm_aeskeygenassist_si128(cipher->key[2], 0x04);
  cipher->key[4] = _mm_aeskeygenassist_si128(cipher->key[3], 0x08);
  cipher->key[5] = _mm_aeskeygenassist_si128(cipher->key[4], 0x10);
  cipher->key[6] = _mm_aeskeygenassist_si128(cipher->key[5], 0x20);
  cipher->key[7] = _mm_aeskeygenassist_si128(cipher->key[6], 0x40);
  cipher->key[8] = _mm_aeskeygenassist_si128(cipher->key[7], 0x80);
  cipher->key[9] = _mm_aeskeygenassist_si128(cipher->key[8], 0x1B);
  cipher->key[10] = _mm_aeskeygenassist_si128(cipher->key[9], 0x36);
  cipher->key[11] = _mm_aeskeygenassist_si128(cipher->key[10], 0x6C);
  cipher->key[12] = _mm_aeskeygenassist_si128(cipher->key[11], 0xD8);
  cipher->key[13] = _mm_aeskeygenassist_si128(cipher->key[12], 0xAB);
  cipher->key[14] = _mm_aeskeygenassist_si128(cipher->key[13], 0x4D);
}

static inline __m128i
garble(cipher *cipher, __m128i a, __m128i b, __m128i c, uint32_t t)
{
  __m128i k;
  __m128i pi;

  k = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi32(a, 1),
                                  _mm_slli_epi32(b, 2)),
                    _mm_set1_epi32(t));

  /* Perform the AES encryption rounds. */
  pi = _mm_xor_si128(k, cipher->key[0]);
  pi = _mm_aesenc_si128(pi, cipher->key[1]);
  pi = _mm_aesenc_si128(pi, cipher->key[2]);
  pi = _mm_aesenc_si128(pi, cipher->key[3]);
  pi = _mm_aesenc_si128(pi, cipher->key[4]);
  pi = _mm_aesenc_si128(pi, cipher->key[5]);
  pi = _mm_aesenc_si128(pi, cipher->key[6]);
  pi = _mm_aesenc_si128(pi, cipher->key[7]);
  pi = _mm_aesenc_si128(pi, cipher->key[8]);
  pi = _mm_aesenc_si128(pi, cipher->key[9]);
  pi = _mm_aesenc_si128(pi, cipher->key[10]);
  pi = _mm_aesenc_si128(pi, cipher->key[11]);
  pi = _mm_aesenc_si128(pi, cipher->key[12]);
  pi = _mm_aesenc_si128(pi, cipher->key[13]);
  pi = _mm_aesenclast_si128(pi, cipher->key[14]);

  return _mm_xor_si128(_mm_xor_si128(pi, k), c);
}

void
report(char *l, struct timeval *begin, struct timeval *end, int rounds)
{
  int64_t d;
  d = (int64_t) end->tv_sec - (int64_t) begin->tv_sec;
  d *= 1000000;
  d += (int64_t) end->tv_usec - (int64_t) begin->tv_usec;
  d *= 1000;
  d *= 100;

  d /= rounds;

  printf("%-20s\t%d\t\t%.2f ns/op\n", l, rounds, (double) d / 100);
}

int
main()
{
  const unsigned char key[AES_BLOCK_SIZE] = "0123456789ABCDEF";
  cipher cipher = {0};
  struct timeval begin, end;
  int rounds = 23802664;
  __m128i a = _mm_set1_epi32(42);
  __m128i b = _mm_set1_epi32(43);
  __m128i c = _mm_set1_epi32(44);
  label la = {42, 0};
  label lb = {43, 0};
  label lc = {44, 0};
  label lr;

  make_cipher(&cipher, key);

  gettimeofday(&begin, NULL);
  for (int i = 0; i < rounds; i++)
    garble(&cipher, a, b, c, (uint32_t) i);
  gettimeofday(&end, NULL);

  report("AES-NI", &begin, &end, rounds);

  gettimeofday(&begin, NULL);
  for (int i = 0; i < rounds; i++)
    garble2(&cipher, &la, &lb, &lc, (uint32_t) i, &lr);
  gettimeofday(&end, NULL);

  report("AES-NI+C", &begin, &end, rounds);


  return 0;
}
