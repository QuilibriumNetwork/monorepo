#include <stdint.h>
#include <stdalign.h>
#include <stdio.h>
#include <x86intrin.h>
#include <math.h>
#include <complex.h>
#include "aesctr.h"
#include "fips202.h"
#include "data.h"
#include "malloc.h"
#include "poly.h"
#include "gaussian.h"
#include "prg_stream.h"

int16_t modp(int64_t a, const pdata prime) {
  int64_t t;

  t  = ((__int128)prime->v64*a + ((__int128)1 << 74)) >> 75;
  t *= prime->p;
  a -= t;
  return a;
}

int16_t pow_simple(int16_t a, int e, const pdata prime) {
  int16_t r;
  if(e == 0) return 1;
  else if(e == 1) return a;
  else if(e < 0) return pow_simple(a,-e*(prime->p-2),prime);

  r = pow_simple(a,e/2,prime);
  if(e&1) r = modp((int64_t)r*r*a,prime);
  else r = modp((int64_t)r*r,prime);

  return r;
}

static int16_t cmodp(int64_t a, const pdata prime) {
  int64_t t;

  t  = (__int128)prime->v64*a >> 75;
  t *= prime->p;
  a -= t;
  t = prime->p/2 - a;
  a -= (t >> 63)&prime->p;
  return a;
}

static int16_t mulmodp(int16_t a, int16_t b, const pdata prime) {
  int32_t c;
  int16_t t;

  c = (int32_t)a*b;
  t = (int16_t)c*prime->pinv;
  t = (c - (int32_t)t*prime->p) >> 16;
  return t;
}

void poly_setzero(poly r) {
  size_t i;
  const __m512i zero = _mm512_setzero_si512();

  for(i=0;i<N/32;i++)
    _mm512_store_si512(&r->v[i],zero);
}

void polyvec_setzero(poly *r, ssize_t stride, size_t len) {
  size_t i,j;
  const __m512i zero = _mm512_setzero_si512();

  for(i=0;i<len;i++)
    for(j=0;j<N/32;j++)
      _mm512_store_si512(&r[i*stride]->v[j],zero);
}

int polyvec_isbinary(const poly *r, ssize_t stride, size_t len) {
  int64_t ret = 0;
  poly t[16];

  while(len >= 16) {
    polyvec_flip(t,r,1,stride,16);
    ret |= polyvec_sprodz(t,r,1,stride,16);

    r += 16;
    len -= 16;
  }
  polyvec_flip(t,r,1,stride,len);
  ret |= polyvec_sprodz(t,r,1,stride,len);

  ret >>= 63;
  return ret+1;
}

void polyvec_fromint64vec(poly *r, const int64_t *a, ssize_t stride, size_t len, size_t deg, const pdata prime) {
  size_t i,j,k;
  int64_t t;

  for(i=0;i<len;i++) {
    for(j=0;j<deg;j++) {
      for(k=0;k<N;k++) {
        t = a[i*deg*N+k*deg+j];
        r[(i*deg+j)*stride]->c[k] = (prime) ? modp(t,prime) : t;
      }
    }
  }
}

void polyvec_copy(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len) {
  size_t i,j;
  __m512i f;

  for(i=0;i<len;i++) {
    for(j=0;j<N/32;j++) {
      f = _mm512_load_si512(&a[stride_a*i]->v[j]);
      _mm512_store_si512(&r[stride_r*i]->v[j],f);
    }
  }
}

void poly_binary_fromuint64(poly r, uint64_t a) {
  size_t i;

  for(i=0;i<64;i++)
    r->c[i] = (a >> i) & 1;
  for(i=64;i<N;i++)
    r->c[i] = 0;
}

static void poly_constant_ntt(poly r, int16_t v, const pdata prime) {
  size_t i;
  __m512i vv;

//  v = mulmodp(v,prime->montsq,prime);
  v = modp((int16_t)v<<16,prime);
  vv = _mm512_set1_epi16(v);
  for(i=0;i<N/32;i++)
    _mm512_store_si512(&r->v[i],vv);
}

void poly_monomial_ntt(poly r, int16_t v, int k, const pdata prime) {
  if(k == 0) {
    poly_constant_ntt(r,v,prime);
    return;
  }

  poly_setzero(r);
  v = mulmodp(v,prime->s,prime);
  r->c[k] = v;
  poly_ntt(r,r,prime);
}

static inline size_t uniform_ref(int16_t *r, size_t len, const uint8_t *buf, size_t buflen, const pdata prime) {
  size_t i,j;
  int s;
  int16_t t,u;
  const int bits = (prime->p & 0x2000) ? 14 : 13;
  const int16_t mask = (1 << bits) - 1;

  i = j = 0;
  s = 0;
  while(i < len && j <= buflen-2) {
    t  = (s) ? (int16_t)buf[j-1] >> (8-s) : 0;
    t |= (int16_t)buf[j+0] << (s+0);
    t |= (int16_t)buf[j+1] << (s+8);
    t &= mask;

    s = s + 16 - bits;
    j += 2 - s/8;
    s %= 8;

    if(t < prime->p) {
      u = ((prime->p-1)/2 - t) >> 15;
      t -= u & prime->p;
      r[i++] = t;
    }
  }

  return i;
}

static inline size_t uniform(int16_t *r, size_t len, const uint8_t *buf, size_t buflen, const pdata prime) {
  size_t i,j;
  const int bits = (prime->p & 0x2000) ? 14 : 13;
  __m512i f,g;
  __mmask32 store, center;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i hp = _mm512_srai_epi16(p,1);
  const __m512i mask = _mm512_set1_epi16((1 << bits) - 1);
  __m512i permbidx,srlvwidx,sllvwidx;
  if(bits == 13) {
    permbidx = _mm512_set_epi8(51,50,49,48,48,47,46,45,44,43,43,42,41,40,40,39,
                               38,37,36,35,35,34,33,32,31,30,30,29,28,27,27,26,
                               25,24,23,22,22,21,20,19,18,17,17,16,15,14,14,13,
                               12,11,10, 9, 9, 8, 7, 6, 5, 4, 4, 3, 2, 1, 1, 0);
    srlvwidx = _mm512_broadcast_i64x2(_mm_set_epi16( 3, 6, 1, 4, 7, 2, 5, 0));
    sllvwidx = _mm512_broadcast_i64x2(_mm_set_epi16(13,10,13,12, 9,13,11,13));
  }
  else {
    permbidx = _mm512_set_epi8(55,54,53,52,51,50,50,49,48,47,46,45,44,43,43,42,
                               41,40,39,38,37,36,36,35,34,33,32,31,30,29,29,28,
                               27,26,25,24,23,22,22,21,20,19,18,17,16,15,15,14,
                               13,12,11,10, 9, 8, 8, 7, 6, 5, 4, 3, 2, 1, 1, 0);
    srlvwidx = _mm512_broadcast_i64x2(_mm_set_epi16( 2, 4, 6, 0, 2, 4, 6, 0));
    sllvwidx = _mm512_broadcast_i64x2(_mm_set_epi16(14,12,10,14,14,12,10,14));
  }

  i = j = 0;
  while(i+32 <= len && j+4*bits <= buflen) {
    f = _mm512_loadu_si512(&buf[j]);
    j += 4*bits;
    f = _mm512_permutexvar_epi8(permbidx,f);
    g = _mm512_alignr_epi8(f,f,2);
    f = _mm512_srlv_epi16(f,srlvwidx);
    g = _mm512_sllv_epi16(g,sllvwidx);
    f = _mm512_or_si512(f,g);
    f = _mm512_and_si512(f,mask);
    store = _mm512_cmp_epi16_mask(f,p,1);
    center = _mm512_cmp_epi16_mask(hp,f,1);
    f = _mm512_mask_sub_epi16(f,center,f,p);
    _mm512_mask_compressstoreu_epi16(&r[i],store,f);
    i += _popcnt32(_cvtmask32_u32(store));
  }

  return i+uniform_ref(r+i,len-i,buf+j,buflen-j,prime);
}

void polyvec_uniform(poly *r, size_t len, const pdata prime, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  size_t k;
  int16_t *coeffs;
  const int16_t p = prime->p;
  const int bits = (p & 0x2000) ? 14 : 13;
  size_t nblocks = ((32*N*bits/8 << bits)/p + AES256CTR_BLOCKBYTES-1)/AES256CTR_BLOCKBYTES;
  alignas(64) uint8_t buf[nblocks*AES256CTR_BLOCKBYTES];
  aes256ctr_ctx aesctx;

  aes256ctr_init(&aesctx,seed,nonce);
  coeffs = r[0]->c;
  len *= N;

  while(len >= 32*N) {
    aes256ctr_squeezeblocks(buf,nblocks,&aesctx);
    k = uniform(coeffs,32*N,buf,nblocks*AES256CTR_BLOCKBYTES,prime);
    coeffs += k;
    len -= k;
  }

  while(len) {
    nblocks = ((len*bits/8 << bits)/p + AES256CTR_BLOCKBYTES-1)/AES256CTR_BLOCKBYTES;
    aes256ctr_squeezeblocks(buf,nblocks,&aesctx);
    k = uniform(coeffs,len,buf,nblocks*AES256CTR_BLOCKBYTES,prime);
    coeffs += k;
    len -= k;
  }
}

/* len must be even */
static inline void ternary_ref(poly *r, ssize_t stride, size_t len, const uint8_t *buf) {
  size_t i,j;
  uint8_t t;
  const uint16_t lut = 0xA815;

  for(i=0;i<len;i++) {
    for(j=0;j<N/2;j++) {
      t = buf[i*N+j];
      r[stride*i]->c[2*j+0]  = (lut >> (t & 0xF)) & 0x3;
      r[stride*i]->c[2*j+0] -= 1;

      r[stride*i]->c[2*j+1]  = (lut >> (t >> 4)) & 0x3;
      r[stride*i]->c[2*j+1] -= 1;
    }
  }
}

static inline void ternary(poly *r, ssize_t stride, size_t len, const uint8_t *buf) {
  size_t i,j;
  __m512i f,g;
  const __m512i one = _mm512_set1_epi16(1);
  const __m512i mask2 = _mm512_set1_epi16(0x3);
  const __m512i mask4 = _mm512_set1_epi16(0xF);
  const __m512i lut = _mm512_set1_epi16((int16_t)0xA815);

  for(i=0;i<len;i++) {
    for(j=0;j<N/32;j++) {
      f = _mm512_cvtepu8_epi32(_mm_load_si128((__m128i*)&buf[16*(N/32*i+j)]));
      g = _mm512_slli_epi32(f,12);
      f = _mm512_or_si512(f,g);
      f = _mm512_and_si512(f,mask4);
      f = _mm512_srlv_epi16(lut,f);
      f = _mm512_and_si512(f,mask2);
      f = _mm512_sub_epi16(f,one);
      _mm512_store_si512(&r[stride*i]->v[j],f);
    }
  }
}

/* Samples ternary polynomials with probabilities 5/16,6/16,5/16 for -1,0,1, respectively (cbd(2) mod 3) */
void polyvec_ternary(poly *r, ssize_t stride, size_t len, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  size_t nblocks;
  alignas(64) uint8_t buf[4096];
  aes256ctr_ctx aesctx;

  aes256ctr_init(&aesctx,seed,nonce);

  while(len >= 8192/N) {
    nblocks = 4096/AES256CTR_BLOCKBYTES;
    aes256ctr_squeezeblocks(buf,nblocks,&aesctx);
    ternary(r,stride,8192/N,buf);
    r += 8192/N*stride;
    len -= 8192/N;
  }

  if(len) {
    nblocks = (len*N/2 + AES256CTR_BLOCKBYTES-1)/AES256CTR_BLOCKBYTES;
    aes256ctr_squeezeblocks(buf,nblocks,&aesctx);
    ternary(r,stride,len,buf);
  }
}

static inline void quarternary(poly *r, ssize_t stride, size_t len, const uint8_t *buf) {
  size_t i,j;
  __m512i f,g;
  const __m512i two = _mm512_set1_epi16(2);
  const __m512i mask2 = _mm512_set1_epi16(0x3);

  for(i=0;i<len;i++) {
    for(j=0;j<N/32;j++) {
      f = _mm512_cvtepu8_epi64(_mm_loadl_epi64((__m128i*)&buf[8*(i*N/32+j)]));
      g = _mm512_slli_epi64(f,28);
      f = _mm512_or_si512(f,g);
      g = _mm512_slli_epi32(f,14);
      f = _mm512_or_si512(f,g);
      f = _mm512_and_si512(f,mask2);
      f = _mm512_sub_epi16(f,two);
      _mm512_store_si512(&r[stride*i]->v[j],f);
    }
  }
}

void polyvec_quarternary(poly *r, ssize_t stride, size_t len, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  size_t nblocks;
  alignas(64) uint8_t buf[4096];
  aes256ctr_ctx aesctx;

  aes256ctr_init(&aesctx,seed,nonce);

  while(len >= 16384/N) {
    nblocks = 4096/AES256CTR_BLOCKBYTES;
    aes256ctr_squeezeblocks(buf,nblocks,&aesctx);
    quarternary(r,stride,16384/N,buf);
    r += 16384/N*stride;
    len -= 16384/N;
  }

  if(len) {
    nblocks = (len*N/4 + AES256CTR_BLOCKBYTES-1)/AES256CTR_BLOCKBYTES;
    aes256ctr_squeezeblocks(buf,nblocks,&aesctx);
    quarternary(r,stride,len,buf);
  }
}

void polyvec_gaussian(poly *r, size_t len, unsigned int log2sd,
                        const uint8_t seed[SEEDLEN], uint64_t nonce) {
  aes256ctr_ctx state;
  int32_t coeffs[N * len];
  size_t i, j;

  aes256ctr_init(&state, seed, nonce);
  quil_prg_stream stream={&state,quil_prg_aes256_squeeze};
  if(quil_gaussian_i32_stream(coeffs, N * len, &stream, log2sd))abort();

  for (i = 0; i < len; i++) {
    for (j = 0; j < N; j++) {
        r[i]->c[j] = coeffs[i * N + j];
    }
  }
}

static inline size_t challenge(poly *c, ssize_t stride, size_t len, const uint8_t *buf, size_t buflen) {
  size_t i,j;
  int k,b;
  uint64_t signs;

  i = j = 0;
  while(i < len && j <= buflen-(TAU1+TAU2+(TAU1+TAU2+7)/8)) {
    signs = 0;
    for(k=0;k<(TAU1+TAU2+7)/8;k++)
      signs |= (uint64_t)buf[j++] << 8*k;

    polyvec_setzero(&c[stride*i],1,1);

    k = N-TAU1-TAU2;
    while(k < N && j < buflen) {
      b = buf[j++] & (N-1);
      if(b <= k) {
        c[stride*i]->c[k] = c[stride*i]->c[b];
        c[stride*i]->c[b] = (k < N-TAU2) ? 1 : 2;
        c[stride*i]->c[b] -= (signs & 1) * (2*c[stride*i]->c[b]);
        signs >>= 1;
        k += 1;
      }
    }

    if(k == N && poly_opnorm(c[stride*i]) <= T)
      i += 1;
  }

  return i;
}

void polyvec_challenge(poly *c, ssize_t stride, size_t len, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  size_t k;
  alignas(64) uint8_t buf[17*SHAKE128_RATE];
  shake128incctx shakectx;

  for(k=0;k<8;k++)
    buf[k] = nonce >> 8*k;

  shake128_inc_init(&shakectx);
  shake128_inc_absorb(&shakectx,seed,SEEDLEN);
  shake128_inc_absorb(&shakectx,buf,8);
  shake128_inc_finalize(&shakectx);

  while(len >= 10) {
    shake128_inc_squeezeblocks(buf,17,&shakectx);
    k = challenge(c,stride,10,buf,17*SHAKE128_RATE);
    len -= k;
    c += k*stride;
  }

  while(len) {
    k = (len*17+9)/10;
    shake128_inc_squeezeblocks(buf,k,&shakectx);
    k = challenge(c,stride,len,buf,k*SHAKE128_RATE);
    len -= k;
    c += k*stride;
  }
}

int64_t polyvec_sprodz_ref(const poly *a, const poly *b, ssize_t stride_a, ssize_t stride_b, size_t len) {
  size_t i,j;
  int64_t t=0;

  for(i=0;i<len;i++)
    for(j=0;j<N;j++)
      t += (int64_t)a[stride_a*i]->c[j]*b[stride_b*i]->c[j];

  return t;
}

int64_t polyvec_sprodz(const poly *a, const poly *b, ssize_t stride_a, ssize_t stride_b, size_t len) {
  size_t i,j;
  __m512i f,g,h,acc;
  __m256i t;
  __m128i u;

  acc = _mm512_setzero_si512();
  while(len) {
    h = _mm512_setzero_si512();
    for(i=0;i<MIN(256/N,len);i++) {
      for(j=0;j<N/32;j++) {
        f = _mm512_load_si512(&a[stride_a*i]->v[j]);
        g = _mm512_load_si512(&b[stride_b*i]->v[j]);
        h = _mm512_dpwssd_epi32(h,f,g);
      }
    }
    f = (__m512i)_mm512_moveldup_ps((__m512)h);
    g = _mm512_srai_epi64(h,32);
    f = _mm512_srai_epi64(f,32);
    acc = _mm512_add_epi64(acc,g);
    acc = _mm512_add_epi64(acc,f);
    a += i;
    b += i;
    len -= i;
  }

  t = _mm256_add_epi64(_mm512_castsi512_si256(acc),_mm512_extracti64x4_epi64(acc,1));
  u = _mm_add_epi64(_mm256_castsi256_si128(t),_mm256_extracti64x2_epi64(t,1));
  u = _mm_add_epi64(u,_mm_unpackhi_epi64(u,u));

  return _mm_extract_epi64(u,0);
}

double polyvec_norm(const poly *a, ssize_t stride, size_t len) {
  return sqrt((double)polyvec_sprodz(a,a,stride,stride,len));
}

void poly_reduce(poly r, const pdata prime) {
#if defined(__aarch64__) && !defined(SIMDE_NO_NATIVE)
  // Preserve the signed high-product and rounded shift exactly. Keeping
  // operations in NEON lanes avoids the emulated 512-bit rounded multiply.
  int16x8_t p=vdupq_n_s16(prime->p), v=vdupq_n_s16(prime->v);
  for(size_t i=0;i<N;i+=8) {
    int16x8_t f=vld1q_s16(&r->c[i]);
    int32x4_t low=vmull_s16(vget_low_s16(f),vget_low_s16(v));
    int32x4_t high=vmull_high_s16(f,v);
    int16x8_t g=vcombine_s16(vshrn_n_s32(low,16),vshrn_n_s32(high,16));
    // mulhrs(g,16) = floor((g + 1024) / 2048), without saturation.
    g=vrshrq_n_s16(g,11);
    vst1q_s16(&r->c[i],vsubq_s16(f,vmulq_s16(g,p)));
  }
#else
  size_t i;
  __m512i f,g;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i v = _mm512_set1_epi16(prime->v);
  const __m512i shift = _mm512_set1_epi16(1 << (16+15-27));

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&r->v[i]);
    g = _mm512_mulhi_epi16(f,v);
    g = _mm512_mulhrs_epi16(g,shift);
    g = _mm512_mullo_epi16(g,p);
    f = _mm512_sub_epi16(f,g);
    _mm512_store_si512(&r->v[i],f);
  }
#endif
}

void polyvec_reduce(poly *r, ssize_t stride, size_t len, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    poly_reduce(r[stride*i],prime);
}

void poly_center(poly r, const pdata prime) {
  size_t i;
  __m512i f;
  __mmask32 mask;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i hp = _mm512_srai_epi16(p,1);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&r->v[i]);
    mask = _mm512_cmp_epi16_mask(hp,f,1);
    f = _mm512_mask_sub_epi16(f,mask,f,p);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polyvec_center(poly *r, ssize_t stride, size_t len, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    poly_center(r[stride*i],prime);
}

void poly_csubp(poly r, const pdata prime) {
  size_t i;
  __m512i f;
  __mmask32 mask;
  const __m512i p = _mm512_set1_epi16(prime->p);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&r->v[i]);
    mask = _mm512_cmp_epi16_mask(p,f,2);
    f = _mm512_mask_sub_epi16(f,mask,f,p);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polyvec_csubp(poly *r, ssize_t stride, size_t len, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    poly_csubp(r[stride*i],prime);
}

void poly_caddp(poly r, const pdata prime) {
#if defined(__aarch64__) && !defined(SIMDE_NO_NATIVE)
  const int16x8_t p=vdupq_n_s16(prime->p);
  for(size_t i=0;i<N;i+=8) {
    int16x8_t f=vld1q_s16(&r->c[i]);
    int16x8_t correction=vandq_s16(vshrq_n_s16(f,15),p);
    vst1q_s16(&r->c[i],vaddq_s16(f,correction));
  }
#else
  size_t i;
  __m512i f;
  __mmask32 mask;
  const __m512i p = _mm512_set1_epi16(prime->p);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&r->v[i]);
    mask = _mm512_movepi16_mask(f);
    f = _mm512_mask_add_epi16(f,mask,f,p);
    _mm512_store_si512(&r->v[i],f);
  }
#endif
}

void polyvec_caddp(poly *r, ssize_t stride, size_t len, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    poly_caddp(r[stride*i],prime);
}

void poly_quot_add(poly r, const poly a, const pdata prime) {
  size_t i;
  __m512i f,g;
  const __m512i v = _mm512_set1_epi16(prime->v);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->v[i]);
    g = _mm512_load_si512(&r->v[i]);
    f = _mm512_mulhi_epi16(f,v);
    f = _mm512_add_epi16(f,g);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polyvec_quot_add(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    poly_quot_add(r[stride_r*i],a[stride_a*i],prime);
}

void poly_neg(poly r, const poly a) {
  size_t i;
  __m512i f;
  const __m512i zero = _mm512_setzero_si512();

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->v[i]);
    f = _mm512_sub_epi16(zero,f);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polyvec_neg(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    poly_neg(r[stride_r*i],a[stride_a*i]);
}

void poly_add(poly r, const poly a, const poly b) {
  size_t i;
  __m512i f,g;

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->v[i]);
    g = _mm512_load_si512(&b->v[i]);
    f = _mm512_add_epi16(f,g);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polyvec_add(poly *r, const poly *a, const poly *b, ssize_t stride_r, ssize_t stride_a, ssize_t stride_b, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    poly_add(r[stride_r*i],a[stride_a*i],b[stride_b*i]);
}

void poly_sub(poly r, const poly a, const poly b) {
  size_t i;
  __m512i f,g;

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->v[i]);
    g = _mm512_load_si512(&b->v[i]);
    f = _mm512_sub_epi16(f,g);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polyvec_sub(poly *r, const poly *a, const poly *b, ssize_t stride_r, ssize_t stride_a, ssize_t stride_b, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    poly_sub(r[stride_r*i],a[stride_a*i],b[stride_b*i]);
}

void poly_ntt_ref(poly r, const poly a, const pdata prime) {
  int len, start, j, k;
  int16_t t, zeta;

  k = 1;
  if(r != a) *r = *a;
  for(len=N/2;len>=1;len>>=1) {
    for(start=0;start<N;start=j+len) {
      zeta = prime->zetas->c[k++];
      for(j=start;j<start+len;j++) {
        t = mulmodp(r->c[j+len],zeta,prime);
        r->c[j+len] = modp(r->c[j] - t,prime);
        r->c[j] = modp(r->c[j] + t,prime);
      }
    }
  }
  poly_scale(r,r,prime->f,prime);
}

void poly_invntt_ref(poly r, const poly a, const pdata prime) {
  int start, len, j, k;
  int16_t t, zeta;

  k = N-1;
  if(r != a) *r = *a;
  for(len=1;len<=N/2;len<<=1) {
    for(start=0;start<N;start=j+len) {
      zeta = prime->zetas->c[k--];
      for(j=start;j<start+len;j++) {
        t = r->c[j];
        r->c[j] = modp(t + r->c[j+len],prime);
        r->c[j+len] = mulmodp(r->c[j+len] - t,zeta,prime);
      }
    }
  }
}

void polyvec_ntt(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    poly_ntt(r[stride_r*i],a[stride_a*i],prime);
}

void polyvec_invntt(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    poly_invntt(r[stride_r*i],a[stride_a*i],prime);
}

void poly_pointwise(poly r, const poly a, const poly b, const pdata prime) {
  size_t i;
  __m512i f,g,h;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->v[i]);
    g = _mm512_load_si512(&b->v[i]);
    h = _mm512_mullo_epi16(f,g);
    f = _mm512_mulhi_epi16(f,g);
    g = _mm512_mullo_epi16(h,pinv);
    g = _mm512_mulhi_epi16(g,p);
    f = _mm512_sub_epi16(f,g);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polyvec_pointwise(poly *r, const poly *a, const poly *b,
                       ssize_t stride_r, ssize_t stride_a, ssize_t stride_b, size_t len, const pdata prime)
{
  size_t i;

  for(i=0;i<len;i++)
    poly_pointwise(r[stride_r*i],a[stride_a*i],b[stride_b*i],prime);
}

void polyvec_poly_pointwise(poly *r, const poly a, const poly *b,
                            ssize_t stride_r, ssize_t stride_b, size_t len, const pdata prime)
{
  size_t i,j;
  __m512i f,g;
  __m512i al[N/32], ah[N/32];
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

  for(i=0;i<N/32;i++) {
    ah[i] = _mm512_load_si512(&a->v[i]);
    al[i] = _mm512_mullo_epi16(ah[i],pinv);
  }

  for(i=0;i<len;i++) {
    for(j=0;j<N/32;j++) {
      f = _mm512_load_si512(&b[stride_b*i]->v[j]);
      g = _mm512_mullo_epi16(f,al[j]);
      f = _mm512_mulhi_epi16(f,ah[j]);
      g = _mm512_mulhi_epi16(g,p);
      f = _mm512_sub_epi16(f,g);
      _mm512_store_si512(&r[stride_r*i]->v[j],f);
    }
  }
}

void poly_pointwise_add(poly r, const poly a, const poly b, const pdata prime) {
  size_t i;
  __m512i f,g,h;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->v[i]);
    g = _mm512_load_si512(&b->v[i]);
    h = _mm512_mullo_epi16(f,g);
    f = _mm512_mulhi_epi16(f,g);
    g = _mm512_mullo_epi16(h,pinv);
    h = _mm512_load_si512(&r->v[i]);
    g = _mm512_mulhi_epi16(g,p);
    f = _mm512_add_epi16(f,h);
    f = _mm512_sub_epi16(f,g);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polyvec_pointwise_add(poly *r, const poly *a, const poly *b,
                           ssize_t stride_r, ssize_t stride_a, ssize_t stride_b, size_t len, const pdata prime)
{
  size_t i;

  for(i=0;i<len;i++)
    poly_pointwise_add(r[stride_r*i],a[stride_a*i],b[stride_b*i],prime);
}

void polyvec_poly_pointwise_add(poly *r, const poly a, const poly *b,
                                ssize_t stride_r, ssize_t stride_b, size_t len, const pdata prime)
{
  size_t i,j;
  __m512i f,g,h;
  __m512i al[N/32], ah[N/32];
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

  for(i=0;i<N/32;i++) {
    ah[i] = _mm512_load_si512(&a->v[i]);
    al[i] = _mm512_mullo_epi16(ah[i],pinv);
  }

  for(i=0;i<len;i++) {
    for(j=0;j<N/32;j++) {
      f = _mm512_load_si512(&b[stride_b*i]->v[j]);
      h = _mm512_load_si512(&r[stride_r*i]->v[j]);
      g = _mm512_mullo_epi16(f,al[j]);
      f = _mm512_mulhi_epi16(f,ah[j]);
      g = _mm512_mulhi_epi16(g,p);
      f = _mm512_add_epi16(f,h);
      f = _mm512_sub_epi16(f,g);
      _mm512_store_si512(&r[stride_r*i]->v[j],f);
    }
  }
}

static inline void polyvec_sprod_add_pair(__m512i *z, const poly *a, const poly *b,
                                          ssize_t stride_z, ssize_t stride_a, ssize_t stride_b)
{
  size_t i;
 __m512i f,g,h,k,u,v;
  const __mmask32 alt = _cvtu32_mask32(0x55555555);

  for(i=0;i<N/32;i++) {
    g = _mm512_load_si512(&a[stride_a]->v[i]);
    k = _mm512_load_si512(&b[stride_b]->v[i]);
    f = _mm512_load_si512(&a[0]->v[i]);
    h = _mm512_load_si512(&b[0]->v[i]);
    u = _mm512_slli_epi32(g,16);
    v = _mm512_slli_epi32(k,16);
    u = _mm512_mask_mov_epi16(u,alt,f);  // FIXME: blend
    v = _mm512_mask_mov_epi16(v,alt,h);
    z[(2*i+0)*stride_z] = _mm512_dpwssd_epi32(z[(2*i+0)*stride_z],u,v);
    u = _mm512_srli_epi32(f,16);
    v = _mm512_srli_epi32(h,16);
    u = _mm512_mask_mov_epi16(g,alt,u);
    v = _mm512_mask_mov_epi16(k,alt,v);
    z[(2*i+1)*stride_z] = _mm512_dpwssd_epi32(z[(2*i+1)*stride_z],u,v);
  }
}

static inline void reduce_mul_add(__m512i *r, const __m512i *a, const __m512i *b, const __m512i x, size_t len,
                                  const pdata prime)
{
  size_t i;
  __m512i f,g;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);
  const __m512i zero = _mm512_setzero_si512();
  const __mmask32 alt = _cvtu32_mask32(0x55555555);

  for(i=0;i<len/2;i++) {
    f = _mm512_srli_epi32(b[2*i+0],16);
    g = _mm512_slli_epi32(b[2*i+1],16);
    g = _mm512_mask_mov_epi16(g,alt,b[2*i+0]);
    f = _mm512_mask_mov_epi16(b[2*i+1],alt,f);
    g = _mm512_mullo_epi16(g,pinv);
    g = _mm512_mulhi_epi16(g,p);
    f = _mm512_sub_epi16(f,g);
    g = _mm512_srli_epi32(f,16);
    f = _mm512_maskz_mov_epi16(alt,f);
    r[2*i+0] = _mm512_dpwssd_epi32((a) ? a[2*i+0] : zero,x,f);
    r[2*i+1] = _mm512_dpwssd_epi32((a) ? a[2*i+1] : zero,x,g);
  }
  if(2*i<len) {
    g = _mm512_mullo_epi16(b[2*i],pinv);
    g = _mm512_mulhi_epi16(g,p);
    f = _mm512_srli_epi32(b[2*i],16);
    f = _mm512_maskz_sub_epi16(alt,f,g);
    r[2*i] = _mm512_dpwssd_epi32((a) ? a[2*i] : zero,x,f);
  }
}

static inline void polyvec_interleave(__m512i *aa, const poly *a0, const poly *a1,
                                      ssize_t stride, size_t len0, size_t len1)
{
  size_t i,j;
  __m512i s,t,u,v;
  const size_t l = MAX(len0,len1);
  const __mmask32 alt = _cvtu32_mask32(0x55555555);

  i = 0;
  while(i<MIN(len0,len1)) {
    for(j=0;j<N/32;j++) {
      s = _mm512_load_si512(&a0[i*stride]->v[j]);
      t = _mm512_load_si512(&a1[i*stride]->v[j]);
      u = _mm512_srli_epi32(s,16);  // TODO: replace with shuffle to avoid blocking ports for mult ins
      v = _mm512_slli_epi32(t,16);
      s = _mm512_mask_mov_epi16(v,alt,s);
      t = _mm512_mask_mov_epi16(t,alt,u);
      _mm512_store_si512(&aa[(2*j+0)*l+i],s);
      _mm512_store_si512(&aa[(2*j+1)*l+i],t);
    }
    i += 1;
  }
  while(i < len0) {
    for(j=0;j<N/32;j++) {
      s = _mm512_load_si512(&a0[i*stride]->v[j]);
      t = _mm512_srli_epi32(s,16);
      s = _mm512_maskz_mov_epi16(alt,s);
      _mm512_store_si512(&aa[(2*j+0)*l+i],s);
      _mm512_store_si512(&aa[(2*j+1)*l+i],t);
    }
    i += 1;
  }
  while(i < len1) {
    for(j=0;j<N/32;j++) {
      s = _mm512_load_si512(&a1[i*stride]->v[j]);
      t = _mm512_slli_epi32(s,16);
      s = _mm512_mask_sub_epi16(s,alt,s,s);
      _mm512_store_si512(&aa[(2*j+0)*l+i],t);
      _mm512_store_si512(&aa[(2*j+1)*l+i],s);
    }
    i += 1;
  }
}

static inline void polyvec_interleave_reduce(poly *r, __m512i *a, ssize_t stride, size_t len, const pdata prime) {
  size_t i,j;
  __m512i f,g,s,t;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);
  const __mmask32 alt = _cvtu32_mask32(0x55555555);

  for(i=0;i<len;i++) {
    for(j=0;j<N/32;j++) {
      f = _mm512_load_si512(&a[(2*j+0)*len+i]);
      g = _mm512_load_si512(&a[(2*j+1)*len+i]);
      s = _mm512_srli_epi32(f,16);
      t = _mm512_slli_epi32(g,16);
      f = _mm512_mask_mov_epi16(t,alt,f);
      g = _mm512_mask_mov_epi16(g,alt,s);
      f = _mm512_mullo_epi16(f,pinv);
      f = _mm512_mulhi_epi16(f,p);
      f = _mm512_sub_epi16(g,f);
      _mm512_store_si512(&r[stride*i]->v[j],f);
    }
  }
}

static inline void polyvec_interleave_reduce_add(poly *r, __m512i *a, ssize_t stride, size_t len, const pdata prime) {
  size_t i,j;
  __m512i f,g,h,s,t;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);
  const __mmask32 alt = _cvtu32_mask32(0x55555555);

  for(i=0;i<len;i++) {
    for(j=0;j<N/32;j++) {
      f = _mm512_load_si512(&a[(2*j+0)*len+i]);
      g = _mm512_load_si512(&a[(2*j+1)*len+i]);
      h = _mm512_load_si512(&r[stride*i]->v[j]);
      s = _mm512_srli_epi32(h,16);
      h = _mm512_maskz_mov_epi16(alt,h);
      f = _mm512_add_epi32(f,h);
      g = _mm512_add_epi32(g,s);
      s = _mm512_srli_epi32(f,16);
      t = _mm512_slli_epi32(g,16);
      f = _mm512_mask_mov_epi16(t,alt,f);
      g = _mm512_mask_mov_epi16(g,alt,s);
      f = _mm512_mullo_epi16(f,pinv);
      f = _mm512_mulhi_epi16(f,p);
      f = _mm512_sub_epi16(g,f);
      _mm512_store_si512(&r[stride*i]->v[j],f);
    }
  }
}

void polyvec_sprod_pointwise(poly r, const poly *a, const poly *b,
                             ssize_t stride_a, ssize_t stride_b, size_t len, const pdata prime)
{
  size_t i;
  size_t chunk = floor(pow(ldexp(1/3.2,31)/(prime->p*prime->p),2));  // 12*sqrt(2*k)*(1.5*p)^2/12<2^31
  __m512i z[2*N/32];
  const __m512i mont = _mm512_set1_epi32(prime->mont);

  for(i=0;i<N/16;i++)
    z[i] = _mm512_setzero_si512();
  while((chunk = MIN(chunk,len) & ~(size_t)1)) {
    for(i=0;i<chunk/2;i++)
      polyvec_sprod_add_pair(z,&a[2*i*stride_a],&b[2*i*stride_b],1,stride_a,stride_b);
    reduce_mul_add(z,NULL,z,mont,N/16,prime);
    a += chunk*stride_a;
    b += chunk*stride_b;
    len -= chunk;
  }
  polyvec_interleave_reduce((poly*)r,z,1,1,prime);
  if(len) {
    poly_pointwise_add(r,a[0],b[0],prime);
    poly_reduce(r,prime);
  }
}

void polyvec_sprod_pointwise_add(poly r, const poly *a, const poly *b,
                                 ssize_t stride_a, ssize_t stride_b, size_t len, const pdata prime)
{
  poly t;

  polyvec_sprod_pointwise(t,a,b,stride_a,stride_b,len,prime);
  poly_add(r,r,t);
}

uint64_t next2power(uint64_t a) {
  a -= 1;
  a |= a >>  1;
  a |= a >>  2;
  a |= a >>  4;
  a |= a >>  8;
  a |= a >> 16;
  a |= a >> 32;
  a += 1;
  return a;
}

size_t extlen(size_t len, size_t deg) {
  size_t mask;

  mask = next2power(deg) - 1;
  return (len + mask) & ~mask;
}

static size_t bitrev(size_t k, size_t n) {
  const size_t t[32] = { 0, 16,  8, 24,  4, 20, 12, 28,
                         2, 18, 10, 26,  6, 22, 14, 30,
                         1, 17,  9, 25,  5, 21, 13, 29,
                         3, 19, 11, 27,  7, 23, 15, 31};

  return t[k] >> (5-n);
}

/* Karatsuba:
   p = floor(n/2), q = ceil(n/2)
   a  = a0 + a1X^p
   b  = b0 + b1X^p
   f  = (a0 - a1)(b0 - b1) = f0 + f1X^p
   g  = a0b0 = g0 + g1X^p
   h  = a1b1 = h0 + h1X^p
   c = fg = g0 + (g1 + g0 + h0 - f0)X^p + (h0 + g1 + h1 - f1)X^2p + h1X^3p
*/
static void polyvec_karatsuba(poly *c, const poly *a, const poly *b, size_t len, const pdata prime) {
  const size_t p = len/2, q = (len+1)/2;
  poly t[2*q-1];

  if(len == 1) {
    poly_pointwise(c[0],a[0],b[0],prime);
    return;
  }
  else if(len == 2) {
    poly_pointwise(c[0],a[0],b[0],prime);
    poly_pointwise(c[1],a[0],b[1],prime);
    poly_pointwise_add(c[1],a[1],b[0],prime);
    poly_pointwise(c[2],a[1],b[1],prime);
    return;
  }

  polyvec_sub(&c[0],&a[0],&a[p],1,1,1,q);
  polyvec_sub(&c[q],&b[0],&b[p],1,1,1,q);
  polyvec_karatsuba(t,&c[0],&c[q],q,prime);  // f
  polyvec_karatsuba(&c[0],&a[0],&b[0],p,prime);  // g
  polyvec_karatsuba(&c[2*p],&a[p],&b[p],q,prime);  // h
  polyvec_add(&c[2*p],&c[p],&c[2*p],1,1,1,p-1);  // g1 + h0
  polyvec_add(&c[p],&c[2*p],&c[0],1,1,1,p);  // g1 + h0 + g0
  polyvec_add(&c[2*p],&c[2*p],&c[3*p],1,1,1,2*q-1-p);  // g1 + h0 + h1
  polyvec_sub(&c[p],&c[p],t,1,1,1,2*q-1);  // g1 + h0 + g0 - f0, g1 + h0 + h1 - f1
  polyvec_reduce(&c[p],1,2*p,prime);
}

static void doublekaratsuba(__m512i *c, const __m512i *a, const __m512i *b, size_t len) {
  size_t i;
  const size_t p = len/2, q = (len+1)/2;
  __m512i t[2*q-1];
  const __m512i zero = _mm512_setzero_si512();

  if(len == 1) {
    *c = _mm512_dpwssd_epi32(zero,*a,*b);
    return;
  }
  else if(len == 2) {
    c[0] = _mm512_dpwssd_epi32(zero,a[0],b[0]);
    c[1] = _mm512_dpwssd_epi32(zero,a[0],b[1]);
    c[1] = _mm512_dpwssd_epi32(c[1],a[1],b[0]);
    c[2] = _mm512_dpwssd_epi32(zero,a[1],b[1]);
    return;
  }
  else if(len == 3) {
    c[0] = _mm512_dpwssd_epi32(zero,a[0],b[0]);
    c[1] = _mm512_dpwssd_epi32(zero,a[0],b[1]);
    c[2] = _mm512_dpwssd_epi32(zero,a[0],b[2]);
    c[3] = _mm512_dpwssd_epi32(zero,a[1],b[2]);
    c[1] = _mm512_dpwssd_epi32(c[1],a[1],b[0]);
    c[2] = _mm512_dpwssd_epi32(c[2],a[1],b[1]);
    c[4] = _mm512_dpwssd_epi32(zero,a[2],b[2]);
    c[3] = _mm512_dpwssd_epi32(c[3],a[2],b[1]);
    c[2] = _mm512_dpwssd_epi32(c[2],a[2],b[0]);
    return;
  }
  else if(len == 4) {
    c[1] = _mm512_dpwssd_epi32(zero,a[0],b[1]);
    c[2] = _mm512_dpwssd_epi32(zero,a[0],b[2]);
    c[3] = _mm512_dpwssd_epi32(zero,a[0],b[3]);
    c[0] = _mm512_dpwssd_epi32(zero,a[0],b[0]);
    c[4] = _mm512_dpwssd_epi32(zero,a[1],b[3]);
    c[1] = _mm512_dpwssd_epi32(c[1],a[1],b[0]);
    c[2] = _mm512_dpwssd_epi32(c[2],a[1],b[1]);
    c[3] = _mm512_dpwssd_epi32(c[3],a[1],b[2]);
    c[5] = _mm512_dpwssd_epi32(zero,a[2],b[3]);
    c[2] = _mm512_dpwssd_epi32(c[2],a[2],b[0]);
    c[3] = _mm512_dpwssd_epi32(c[3],a[2],b[1]);
    c[4] = _mm512_dpwssd_epi32(c[4],a[2],b[2]);
    c[6] = _mm512_dpwssd_epi32(zero,a[3],b[3]);
    c[3] = _mm512_dpwssd_epi32(c[3],a[3],b[0]);
    c[4] = _mm512_dpwssd_epi32(c[4],a[3],b[1]);
    c[5] = _mm512_dpwssd_epi32(c[5],a[3],b[2]);
    return;
  }

  for(i=0;i<q;i++) {
    c[0+i] = _mm512_sub_epi16(a[0+i],a[p+i]);
    c[q+i] = _mm512_sub_epi16(b[0+i],b[p+i]);
  }
  doublekaratsuba(t,&c[0],&c[q],q);
  doublekaratsuba(&c[0],&a[0],&b[0],p);
  doublekaratsuba(&c[2*p],&a[p],&b[p],q);
  for(i=0;i<p-1;i++)
    c[2*p+i] = _mm512_add_epi32(c[p+i],c[2*p+i]);
  for(i=0;i<p;i++)
    c[p+i] = _mm512_add_epi32(c[2*p+i],c[0+i]);
  for(i=0;i<2*q-1-p;i++)
    c[2*p+i] = _mm512_add_epi32(c[2*p+i],c[3*p+i]);
  for(i=0;i<2*q-1;i++)
    c[p+i] = _mm512_sub_epi32(c[p+i],t[i]);
}

static inline void doubleschoolbook(__m512i *c, __m512i *a, __m512i *b, size_t deg, size_t clen, size_t blen,
                                    __m512i x, const pdata prime)
{
  size_t i,j;
  const size_t olen = MIN(clen,blen-1);
  __m512i f,g,h[clen+olen];
  const __m512i mont = _mm512_set1_epi32(prime->mont);

  for(i=0;i<clen;i++)
    h[i] = _mm512_load_si512(&c[i]);
  for(i=0;i<olen;i++)
    h[clen+i] = _mm512_setzero_si512();

  for(j=0;j<blen;j++) {
    f = _mm512_load_si512(&b[j]);
    for(i=0;i<j && i<clen;i++) {
      g = _mm512_load_si512(&a[deg+i-j]);
      h[clen+i] = _mm512_dpwssd_epi32(h[clen+i],f,g);
    }
    for(i=j;i<deg && i<clen;i++) {
      g = _mm512_load_si512(&a[i-j]);
      h[i] = _mm512_dpwssd_epi32(h[i],f,g);
    }
  }

  reduce_mul_add(&h[0],&h[0],&h[clen],x,olen,prime);
  reduce_mul_add(&h[0],NULL,&h[0],mont,clen,prime);
  for(i=0;i<clen;i++)
    _mm512_store_si512(&c[i],h[i]);
}

static inline void doubleschoolbook_conj(__m512i *c, __m512i *a, __m512i *b, size_t deg, size_t clen, size_t blen,
                                         __m512i x, const pdata prime)
{
  size_t i,j;
  const size_t olen = clen;
  __m512i f,g,h[clen+olen];
  const __m512i mont = _mm512_set1_epi32(prime->mont);

  for(i=0;i<clen+olen;i++)
    h[i] = _mm512_setzero_si512();

  for(i=0;i<blen;i++) {
    f = _mm512_load_si512(&b[i]);
    for(j=0;j<=i && j<clen;j++) {
      g = _mm512_load_si512(&a[i-j]);
      h[j] = _mm512_dpwssd_epi32(h[j],f,g);
    }
    for(j=i+1;j<deg && j<clen;j++) {
      g = _mm512_load_si512(&a[deg+i-j]);
      h[clen+j] = _mm512_dpwssd_epi32(h[clen+j],f,g);
    }
  }

  reduce_mul_add(&h[0],&h[0],&h[clen],x,olen,prime);
  reduce_mul_add(&h[0],NULL,&h[0],mont,clen,prime);
  for(i=0;i<clen;i++)
    _mm512_store_si512(&c[i],h[i]);
}

void polyvec_sprod_extension(poly *c, const poly *a, const poly *b,
                             ssize_t stride_c, ssize_t stride_a, ssize_t stride_b,
                             size_t deg, size_t clen, size_t blen,
                             const pdata prime)
{
  size_t i,j;
  poly x;
  __m512i aa[2*deg*N/32], bb[2*deg*N/32], cc[2*clen*N/32], xx[2*N/32];
  const __m512i zero = _mm512_setzero_si512();

  /* shortcut */
  if(deg == 1) {
    polyvec_sprod_pointwise(c[0],a,b,stride_a,stride_b,blen,prime);
    return;
  }

  for(i=0;i<clen*N/16;i++)
    _mm512_store_si512(&cc[i],zero);
  poly_monomial_ntt(x,1,1,prime);
  polyvec_interleave(xx,&x,NULL,1,1,0);
  while(blen >= 2*deg) {
    polyvec_interleave(aa,&a[0],&a[stride_a*deg],stride_a,deg,deg);
    polyvec_interleave(bb,&b[0],&b[stride_b*deg],stride_b,deg,deg);
    for(i=0;i<N/16;i++)
      doubleschoolbook(&cc[i*clen],&aa[i*deg],&bb[i*deg],deg,clen,deg,xx[i],prime);
    a += 2*deg*stride_a;
    b += 2*deg*stride_b;
    blen -= 2*deg;
  }

  while(blen) {
    j = MIN(blen,deg);
    polyvec_interleave(aa,a,NULL,stride_a,deg,0);
    polyvec_interleave(bb,b,NULL,stride_b,j,0);
    for(i=0;i<N/16;i++)
      doubleschoolbook(&cc[i*clen],&aa[i*deg],&bb[i*j],deg,clen,j,xx[i],prime);
    a += deg*stride_a;
    b += j*stride_b;
    blen -= j;
  }

  polyvec_interleave_reduce(c,cc,stride_c,clen,prime);
}

void polyvec_collaps_add_extension(poly *c, const poly *b, const poly *a,
                                   ssize_t stride_c, ssize_t stride_b, ssize_t stride_a,
                                   size_t deg, size_t clen, size_t blen,
                                   const pdata prime)
{
  size_t i,l;
  poly x,t[deg];
  __m512i aa[deg*N/32], bb0[deg*N/32], bb1[deg*N/32], cc[2*deg*N/32], xx[2*N/32];

  /* shortcut */
  if(deg == 1) {
    polyvec_poly_pointwise(c,b[0],a,stride_c,stride_a,clen,prime);
    return;
  }

  poly_monomial_ntt(x,1,1,prime);
  polyvec_copy(&t[0],&b[2*stride_b],1,stride_b,blen-2);
  polyvec_setzero(&t[blen-2],1,deg-blen);
  polyvec_poly_pointwise(&t[deg-2],x,&b[0],1,stride_b,2,prime);
  polyvec_interleave(bb0,&b[0],&b[stride_b],2*stride_b,(blen+1)/2,blen/2);
  polyvec_interleave(bb1,&b[1],&t[0],2,blen/2,deg/2);

  deg = deg/2;
  blen = (blen+1)/2;
  polyvec_interleave(xx,&x,NULL,1,1,0);
  while(clen) {
    l = MIN(clen,2*deg);
    polyvec_interleave(aa,&a[0],&a[1],2*stride_a,deg,deg);
    for(i=0;i<N/16;i++) {
      doubleschoolbook_conj(&cc[(l+1)/2*i],&aa[i*deg],&bb0[i*blen],deg,(l+1)/2,blen,xx[i],prime);
      doubleschoolbook_conj(&cc[deg*N/16+l/2*i],&aa[i*deg],&bb1[i*deg],deg,l/2,deg,xx[i],prime);
    }
    polyvec_interleave_reduce_add(&c[0],&cc[0],2*stride_c,(l+1)/2,prime);
    polyvec_interleave_reduce_add(&c[stride_c],&cc[deg*N/16],2*stride_c,l/2,prime);
    c += l*stride_c;
    a += 2*deg*stride_a;
    clen -= l;
  }
}

static void polyvec_pairwise_sprod_add_pair(__m512i *g, const poly *a, const poly *b,
                                            size_t m, size_t n, size_t r, size_t s, int triag)
{
  size_t k,l;

  if(!r || !s) {
    return;
  }
  else if(r == 1 && s == 1) {
    polyvec_sprod_add_pair(g,a,b,m,1,1);
    return;
  }

  k = (r+1)/2;
  l = (s+1)/2;
  if(triag) {
    // r == s
    polyvec_pairwise_sprod_add_pair(&g[0],&a[0*n],&b[0*n],m,n,k,k,1);
    polyvec_pairwise_sprod_add_pair(&g[(k*k+k)/2],&a[k*n],&b[k*n],m,n,r-k,r-k,1);
    polyvec_pairwise_sprod_add_pair(&g[(k*k+(r-k)*(r-k)+r)/2],&a[0*n],&b[k*n],m,n,k,r-k,0);
    if(a != b)
      polyvec_pairwise_sprod_add_pair(&g[(k*k+(r-k)*(r-k)+r)/2],&a[k*n],&b[0*n],m,n,r-k,k,0);
  }
  else {
    polyvec_pairwise_sprod_add_pair(&g[0],&a[0*n],&b[0*n],m,n,k,l,0);
    polyvec_pairwise_sprod_add_pair(&g[k*l],&a[k*n],&b[l*n],m,n,r-k,s-l,0);
    polyvec_pairwise_sprod_add_pair(&g[k*l+(r-k)*(s-l)],&a[0*n],&b[l*n],m,n,k,s-l,0);
    polyvec_pairwise_sprod_add_pair(&g[k*l+(r-k)*(s-l)+k*(s-l)],&a[k*n],&b[0*n],m,n,r-k,l,0);
  }
}

static size_t _pwidx(size_t i, size_t j, size_t r, size_t s, int triag) {
  size_t k,l;

  if(r <= 1 && s <= 1)
    return 0;

  k = (r+1)/2;
  l = (s+1)/2;
  if(triag) {
    // r == s, i <= j
    if(j < k)
      return _pwidx(i,j,k,k,1);
    else if(i >= k)
      return (k*k+k)/2 + _pwidx(i-k,j-k,r-k,r-k,1);
    else
      return (k*k+(r-k)*(r-k)+r)/2 + _pwidx(i,j-k,k,r-k,0);
  }
  else {
    if(i < k && j < l)
      return _pwidx(i,j,k,l,0);
    else if(i >= k && j >= l)
      return k*l + _pwidx(i-k,j-l,r-k,s-l,0);
    else if(i < k)
      return k*l + (r-k)*(s-l) + _pwidx(i,j-l,k,s-l,0);
    else
      return k*l + (r-k)*(s-l) + k*(s-l) + _pwidx(i-k,j,r-k,l,0);
  }
}

size_t pwidx(size_t i, size_t j, size_t r) {
  if(i>j) {  // swap
    j ^= i;
    i ^= j;
    j ^= i;
  }
  return _pwidx(i,j,r,r,1);
}

void polyvec_pairwise_pointwise(poly *g, const poly *a, const poly *b,
                                ssize_t stride_g, ssize_t stride_a, ssize_t stride_b,
                                size_t r, size_t s,
                                const pdata prime)
{
  size_t k,l;

  if(!r || !s) {
    return;
  }
  else if(r == 1 && s == 1) {
    poly_pointwise(*g,*a,*b,prime);
    return;
  }

  k = (r+1)/2;
  l = (s+1)/2;
  if(a == b) {
    // r == s
    polyvec_pairwise_pointwise(&g[0],&a[0],&b[0],stride_g,stride_a,stride_b,k,k,prime);
    polyvec_pairwise_pointwise(&g[(k*k+k)/2*stride_g],&a[k*stride_a],&b[k*stride_b],
                               stride_g,stride_a,stride_b,r-k,r-k,prime);
    polyvec_pairwise_pointwise(&g[((k*k+(r-k)*(r-k)+r)/2)*stride_g],&a[0],&b[k*stride_b],
                               stride_g,stride_a,stride_b,k,r-k,prime);
  }
  else {
    polyvec_pairwise_pointwise(&g[0],&a[0],&b[0],stride_g,stride_a,stride_b,k,l,prime);
    polyvec_pairwise_pointwise(&g[k*l*stride_g],&a[k*stride_a],&b[l*stride_b],
                               stride_g,stride_a,stride_b,r-k,s-l,prime);
    polyvec_pairwise_pointwise(&g[(k*l+(r-k)*(s-l))*stride_g],&a[0],&b[l*stride_b],
                               stride_g,stride_a,stride_b,k,s-l,prime);
    polyvec_pairwise_pointwise(&g[(k*l+(r-k)*(s-l)+k*(s-l))*stride_g],&a[k*stride_a],&b[0],
                               stride_g,stride_a,stride_b,r-k,l,prime);
  }
}

static void polyvec_pairwise_doubleoffdiag(poly *g, size_t r, const pdata prime) {
  size_t k;

  if(r <= 1)
    return;

  k = (r+1)/2;
  polyvec_pairwise_doubleoffdiag(&g[0],k,prime);
  polyvec_pairwise_doubleoffdiag(&g[(k*k+k)/2],r-k,prime);
  g += (k*k+(r-k)*(r-k)+r)/2;
  polyvec_add(g,g,g,1,1,1,(r-k)*k);
  polyvec_reduce(g,1,(r-k)*k,prime);
}

void polyvec_pairwise_sprod(poly *g, const poly *a, const poly *b, size_t r, size_t n, const pdata prime) {
  size_t i,j;
  size_t k = floor(pow(ldexp(1/3.2,31)/(prime->p*prime->p),2));
  const size_t m = (r*r+r)/2;
  __m512i *z;
  const __m512i mont = _mm512_set1_epi32(prime->mont);

  z = _aligned_calloc(64,2*N/32*m*sizeof(__m512i));
  for(j=0;(k=MIN(k,n-j)&~1);j+=k) {
    for(i=j;i<j+k;i+=2)
      polyvec_pairwise_sprod_add_pair(z,&a[i],&b[i],m,n,r,r,1);
    reduce_mul_add(z,NULL,z,mont,2*N/32*m,prime);
  }
  polyvec_interleave_reduce(g,z,1,m,prime);
  if(n & 1) {
    polyvec_pairwise_pointwise((poly*)z,&a[n-1],&b[n-1],1,n,n,r,r,prime);
    polyvec_add(g,g,(poly*)z,1,1,1,m);
    polyvec_reduce(g,1,m,prime);
  }
  if(a == b)
    polyvec_pairwise_doubleoffdiag(g,r,prime);
}

void poly_scale(poly r, const poly a, int16_t s, const pdata prime) {
  size_t i;
  __m512i f,g;
  const __m512i l = _mm512_set1_epi16(s*prime->pinv);
  const __m512i h = _mm512_set1_epi16(s);
  const __m512i p = _mm512_set1_epi16(prime->p);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->v[i]);
    g = _mm512_mullo_epi16(f,l);
    f = _mm512_mulhi_epi16(f,h);
    g = _mm512_mulhi_epi16(g,p);
    f = _mm512_sub_epi16(f,g);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polyvec_scale(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, int16_t s, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    poly_scale(r[stride_r*i],a[stride_a*i],s,prime);
}

void poly_scale_add(poly r, const poly a, int16_t s, const pdata prime) {
  poly t;

  poly_scale(t,a,s,prime);
  poly_add(r,r,t);
}

void polyvec_scale_add(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, int16_t s, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    poly_scale_add(r[stride_r*i],a[stride_a*i],s,prime);
}

void poly_mul(poly r, const poly a, const poly b, const pdata prime) {
  poly ah;

  poly_ntt(ah,a,prime);
  poly_ntt(r,b,prime);
  poly_pointwise(r,ah,r,prime);
  poly_invntt(r,r,prime);
  poly_scale(r,r,prime->u,prime);
}

static const double complex czetas[128] = {
   0.0                     + 1.0                    *I,
   0.70710678118654752440  + 0.70710678118654752440 *I,
   0.92387953251128675613  + 0.38268343236508977173 *I,
  -0.38268343236508977173  + 0.92387953251128675613 *I,
   0.98078528040323044913  + 0.19509032201612826785 *I,
  -0.19509032201612826785  + 0.98078528040323044913 *I,
   0.55557023301960222474  + 0.83146961230254523708 *I,
  -0.83146961230254523708  + 0.55557023301960222474 *I,
   0.99518472667219688624  + 0.098017140329560601994*I,
  -0.098017140329560601994 + 0.99518472667219688624 *I,
   0.63439328416364549822  + 0.77301045336273696081 *I,
  -0.77301045336273696081  + 0.63439328416364549822 *I,
   0.88192126434835502971  + 0.47139673682599764856 *I,
  -0.47139673682599764856  + 0.88192126434835502971 *I,
   0.29028467725446236764  + 0.95694033573220886494 *I,
  -0.95694033573220886494  + 0.29028467725446236764 *I,
   0.99879545620517239271  + 0.049067674327418014255*I,
  -0.049067674327418014255 + 0.99879545620517239271 *I,
   0.67155895484701840063  + 0.74095112535495909118 *I,
  -0.74095112535495909118  + 0.67155895484701840063 *I,
   0.90398929312344333159  + 0.42755509343028209432 *I,
  -0.42755509343028209432  + 0.90398929312344333159 *I,
   0.33688985339222005069  + 0.94154406518302077841 *I,
  -0.94154406518302077841  + 0.33688985339222005069 *I,
   0.97003125319454399260  + 0.24298017990326388995 *I,
  -0.24298017990326388995  + 0.97003125319454399260 *I,
   0.51410274419322172659  + 0.85772861000027206990 *I,
  -0.85772861000027206990  + 0.51410274419322172659 *I,
   0.80320753148064490981  + 0.59569930449243334347 *I,
  -0.59569930449243334347  + 0.80320753148064490981 *I,
   0.14673047445536175166  + 0.98917650996478097345 *I,
  -0.98917650996478097345  + 0.14673047445536175166 *I,
   0.99969881869620422012  + 0.024541228522912288032*I,
  -0.024541228522912288032 + 0.99969881869620422012 *I,
   0.68954054473706692462  + 0.72424708295146692094 *I,
  -0.72424708295146692094  + 0.68954054473706692462 *I,
   0.91420975570353065464  + 0.40524131400498987091 *I,
  -0.40524131400498987091  + 0.91420975570353065464 *I,
   0.35989503653498814878  + 0.93299279883473888771 *I,
  -0.93299279883473888771  + 0.35989503653498814878 *I,
   0.97570213003852854446  + 0.21910124015686979723 *I,
  -0.21910124015686979723  + 0.97570213003852854446 *I,
   0.53499761988709721066  + 0.84485356524970707326 *I,
  -0.84485356524970707326  + 0.53499761988709721066 *I,
   0.81758481315158369650  + 0.57580819141784530075 *I,
  -0.57580819141784530075  + 0.81758481315158369650 *I,
   0.17096188876030122636  + 0.98527764238894124477 *I,
  -0.98527764238894124477  + 0.17096188876030122636 *I,
   0.99247953459870999816  + 0.12241067519921619850 *I,
  -0.12241067519921619850  + 0.99247953459870999816 *I,
   0.61523159058062684548  + 0.78834642762660626201 *I,
  -0.78834642762660626201  + 0.61523159058062684548 *I,
   0.87008699110871141865  + 0.49289819222978403687 *I,
  -0.49289819222978403687  + 0.87008699110871141865 *I,
   0.26671275747489838633  + 0.96377606579543986669 *I,
  -0.96377606579543986669  + 0.26671275747489838633 *I,
   0.94952818059303666720  + 0.31368174039889147666 *I,
  -0.31368174039889147666  + 0.94952818059303666720 *I,
   0.44961132965460660005  + 0.89322430119551532034 *I,
  -0.89322430119551532034  + 0.44961132965460660005 *I,
   0.75720884650648454758  + 0.65317284295377676408 *I,
  -0.65317284295377676408  + 0.75720884650648454758 *I,
   0.073564563599667423529 + 0.99729045667869021614 *I,
  -0.99729045667869021614  + 0.073564563599667423529*I,
   0.99992470183914454092  + 0.012271538285719926079*I,
  -0.012271538285719926079 + 0.99992470183914454092 *I,
   0.69837624940897285355  + 0.71573082528381865413 *I,
  -0.71573082528381865413  + 0.69837624940897285355 *I,
   0.91911385169005774391  + 0.39399204006104810860 *I,
  -0.39399204006104810860  + 0.91911385169005774391 *I,
   0.37131719395183754341  + 0.92850608047321556594 *I,
  -0.92850608047321556594  + 0.37131719395183754341 *I,
   0.97831737071962763311  + 0.20711137619221854971 *I,
  -0.20711137619221854971  + 0.97831737071962763311 *I,
   0.54532498842204642231  + 0.83822470555483804319 *I,
  -0.83822470555483804319  + 0.54532498842204642231 *I,
   0.82458930278502526447  + 0.56573181078361319739 *I,
  -0.56573181078361319739  + 0.82458930278502526447 *I,
   0.18303988795514095852  + 0.98310548743121632718 *I,
  -0.98310548743121632718  + 0.18303988795514095852 *I,
   0.99390697000235604155  + 0.11022220729388305881 *I,
  -0.11022220729388305881  + 0.99390697000235604155 *I,
   0.62485948814238637708  + 0.78073722857209447830 *I,
  -0.78073722857209447830  + 0.62485948814238637708 *I,
   0.87607009419540660710  + 0.48218377207912274852 *I,
  -0.48218377207912274852  + 0.87607009419540660710 *I,
   0.27851968938505310521  + 0.96043051941556581120 *I,
  -0.96043051941556581120  + 0.27851968938505310521 *I,
   0.95330604035419383692  + 0.30200594931922806700 *I,
  -0.30200594931922806700  + 0.95330604035419383692 *I,
   0.46053871095824002363  + 0.88763962040285394776 *I,
  -0.88763962040285394776  + 0.46053871095824002363 *I,
   0.76516726562245892589  + 0.64383154288979146507 *I,
  -0.64383154288979146507  + 0.76516726562245892589 *I,
   0.085797312344439890462 + 0.99631261218277801263 *I,
  -0.99631261218277801263  + 0.085797312344439890462*I,
   0.99811811290014920713  + 0.061320736302208577783*I,
  -0.061320736302208577783 + 0.99811811290014920713 *I,
   0.66241577759017176111  + 0.74913639452345932547 *I,
  -0.74913639452345932547  + 0.66241577759017176111 *I,
   0.89867446569395384304  + 0.43861623853852763765 *I,
  -0.43861623853852763765  + 0.89867446569395384304 *I,
   0.32531029216226293414  + 0.94560732538052132573 *I,
  -0.94560732538052132573  + 0.32531029216226293414 *I,
   0.96697647104485210909  + 0.25486565960451457155 *I,
  -0.25486565960451457155  + 0.96697647104485210909 *I,
   0.50353838372571755869  + 0.86397285612158673792 *I,
  -0.86397285612158673792  + 0.50353838372571755869 *I,
   0.79583690460888353626  + 0.60551104140432551392 *I,
  -0.60551104140432551392  + 0.79583690460888353626 *I,
   0.13458070850712618632  + 0.99090263542778002511 *I,
  -0.99090263542778002511  + 0.13458070850712618632 *I,
   0.98730141815785838240  + 0.15885814333386144168 *I,
  -0.15885814333386144168  + 0.98730141815785838240 *I,
   0.58579785745643886033  + 0.81045719825259479173 *I,
  -0.81045719825259479173  + 0.58579785745643886033 *I,
   0.85135519310526514226  + 0.52458968267846890622 *I,
  -0.52458968267846890622  + 0.85135519310526514226 *I,
   0.23105810828067111964  + 0.97293995220556014547 *I,
  -0.97293995220556014547  + 0.23105810828067111964 *I,
   0.93733901191257492320  + 0.34841868024943456842 *I,
  -0.34841868024943456842  + 0.93733901191257492320 *I,
   0.41642956009763718256  + 0.90916798309052237656 *I,
  -0.90916798309052237656  + 0.41642956009763718256 *I,
   0.73265427167241283462  + 0.68060099779545305059 *I,
  -0.68060099779545305059  + 0.73265427167241283462 *I,
   0.036807222941358832324 + 0.99932238458834950090 *I,
  -0.99932238458834950090  + 0.036807222941358832324*I,
};

void poly_fft(double complex r[N/2], const poly a) {
  size_t len, start, j, k;
  double complex t;

  for(j=0;j<N/2;j++)
    r[j] = a->c[j] + a->c[N/2+j]*I;

  k = 1;
  for(len=N/4;len>=1;len>>=1) {
    for(start=0;start<N/2;start=j+len) {
      for(j=start;j<start+len;j++) {
        t = r[j+len]*czetas[k];
        r[j+len] = r[j] - t;
        r[j] = r[j] + t;
      }
      k += 1;
    }
  }
}

void poly_invfft(poly r, double complex a[N/2]) {
  size_t start, len, j, k;
  double complex u;

  k = N/4;
  for(len=1;len<=N/4;len<<=1) {
    for(start=0;start<N/2;start=j+len) {
      for(j=start;j<start+len;j++) {
        u = a[j] - a[j+len];
        a[j] = a[j] + a[j+len];
        a[j+len] = u*conj(czetas[k]);
      }
      k += 1;
    }
    k /= 4;
  }

  for(j=0;j<N/2;j++) {
    a[j] = 2*a[j]/N;
    r->c[j] = round(creal(a[j]));
    r->c[j+N/2] = round(cimag(a[j]));
  }
}

double poly_opnorm(const poly a) {
  size_t i;
  double complex vec[N/2];
  double t,r = 0;

  poly_fft(vec,a);
  for(i=0;i<N/2;i++) {
    t = cabs(vec[i]);
    if(t > r) r = t;
  }

  return r;
}

void poly_sigmam1(poly r, const poly a) {
  size_t i;
  __m512i f,g;
  const __m512i permwidx = _mm512_set_epi16( 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
                                            16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31);
  const __m512i zero = _mm512_setzero_si512();

  r->c[0] = a->c[0];
  for(i=0;i<N/64;i++) {
    f = _mm512_loadu_si512(&a->c[32*i+1]);
    g = _mm512_load_si512(&a->v[N/32-1-i]);
    f = _mm512_permutexvar_epi16(permwidx,f);
    g = _mm512_permutexvar_epi16(permwidx,g);
    f = _mm512_sub_epi16(zero,f);
    g = _mm512_sub_epi16(zero,g);
    _mm512_storeu_si512(&r->c[32*i+1],g);
    _mm512_store_si512(&r->v[N/32-1-i],f);
  }
}

void polyvec_sigmam1(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    poly_sigmam1(r[stride_r*i],a[stride_a*i]);
}

void poly_sigmam1_ntt(poly r, const poly a) {
  size_t i;
  __m512i f,g;
  const __m512i permwidx = _mm512_set_epi16( 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
                                            16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31);

  for(i=0;i<N/64;i++) {
    f = _mm512_load_si512(&a->v[i]);
    g = _mm512_load_si512(&a->v[N/32-1-i]);
    f = _mm512_permutexvar_epi16(permwidx,f);
    g = _mm512_permutexvar_epi16(permwidx,g);
    _mm512_store_si512(&r->v[N/32-1-i],f);
    _mm512_store_si512(&r->v[i],g);
  }
}

void polyvec_sigmam1_ntt(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    poly_sigmam1_ntt(r[stride_r*i],a[stride_a*i]);
}

void poly_sigma(poly r, const poly a, int k) {
  size_t i,j;
  int16_t x;
  poly t;

  j = 0;
  for(i=0;i<N;i++) {
    x = a->c[i];
    x ^= (-(j&N) >> 31) & (x ^ -x);
    t->c[j&(N-1)] = x;
    j += k;
  }

  *r = *t;
}

void poly_sigma5(poly r, const poly a) {
  poly_sigma(r,a,5);
}

void polyvec_sigma5(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    poly_sigma(r[stride_r*i],a[stride_a*i],5);
}

void poly_sigma5inv(poly r, const poly a) {
  poly_sigma(r,a,3277);
}

void polyvec_sigma5inv(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    poly_sigma(r[stride_r*i],a[stride_a*i],3277);  // assumes N <= 8192
}

void poly_flip(poly r, const poly a) {
  size_t i;
  __m512i f;
  const __m512i ones = _mm512_set1_epi16(1);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->v[i]);
    f = _mm512_sub_epi16(ones,f);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polyvec_flip(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    poly_flip(r[stride_r*i],a[stride_a*i]);
}

void poly_flip_ntt(poly r, const poly a, const pdata prime) {
  size_t i;
  __m512i f;
  poly t;

  f = _mm512_set1_epi16(mulmodp(1,prime->s,prime));
  for(i=0;i<N/32;i++)
    _mm512_store_si512(&t->v[i],f);
  poly_ntt(t,t,prime);
  poly_sub(r,t,a);
  poly_sigmam1_ntt(r,r);
}

void polyvec_flip_ntt(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    poly_flip_ntt(r[stride_r*i],a[stride_a*i],prime);
}

void poly_print(const poly a) {
  size_t i;

  for(i=0;i<N;i++) {
    printf("%2zu: ", i);
    printf("%5d", a->c[i]);
    printf("\n");
  }
}

void polyvec_print(const poly* a, ssize_t stride, size_t len) {
  size_t i;

  for(i=0;i<len;i++){
    printf("poly %zu:\n", i);
    poly_print(a[stride*i]);
  }
}

void poly_rotate(poly r, const poly a, size_t k) {
  size_t i,j;
  __m512i f;
  __mmask32 neg;
  poly t;
  poly_ptr b = (r==a) ? t : r;
  const __mmask32 mask = _cvtu32_mask32((uint32_t)-1 >> (k%32));
  const __m512i zero = _mm512_setzero_si512();

  k %= 2*N;
  neg = _cvtu32_mask32(-(k/N));
  i = 0;
  j = k % N;
  while(j <= N-32) {
    f = _mm512_load_si512(&a->v[i]);
    f = _mm512_mask_sub_epi16(f,neg,zero,f);
    _mm512_storeu_si512(&b->c[j],f);
    i += 1;
    j += 32;
  }
  if(j < N) {
    f = _mm512_load_si512(&a->v[i]);
    f = _mm512_mask_sub_epi16(f,neg,zero,f);
    _mm512_mask_storeu_epi16(&b->c[j],mask,f);
    f = _mm512_sub_epi16(zero,f);
    _mm512_mask_storeu_epi16(&b->c[j-N],_knot_mask32(mask),f);
    i += 1;
    j += 32;
  }
  j -= N;
  neg = _knot_mask32(neg);
  while(i < N/32) {
    f = _mm512_load_si512(&a->v[i]);
    f = _mm512_mask_sub_epi16(f,neg,zero,f);
    _mm512_storeu_si512(&b->c[j],f);
    i += 1;
    j += 32;
  }

  if(r == a) *r = *b;
}

/* Compute FFT over Rq[Y]/(Y^d - X^k) where Rq = Zq[X]/(X^N + 1) */
void polyvec_cfft(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t d, size_t k) {
  size_t i;
  poly t;

  d /= 2;
  k /= 2;
  for(i=0;i<d;i++) {
    poly_rotate(t,a[(d+i)*stride_a],k);
    poly_sub(r[(d+i)*stride_r],a[stride_a*i],t);
    poly_add(r[stride_r*i],a[stride_a*i],t);
  }
  if(d > 1) {
    polyvec_cfft(&r[0],&r[0],stride_r,stride_r,d,k);
    polyvec_cfft(&r[stride_r*d],&r[stride_r*d],stride_r,stride_r,d,N+k);
  }
}

void polyvec_cinvfft(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t d, size_t k) {
  size_t i;
  poly t;

  d /= 2;
  k /= 2;
  if(d > 1) {
    polyvec_cinvfft(&r[0],&a[0],stride_r,stride_a,d,k);
    polyvec_cinvfft(&r[stride_r*d],&a[stride_a*d],stride_r,stride_a,d,N+k);
    a = r;
  }
  for(i=0;i<d;i++) {
    poly_sub(t,a[stride_a*i],a[(d+i)*stride_a]);
    poly_add(r[stride_r*i],a[stride_a*i],a[(d+i)*stride_a]);
    poly_rotate(r[(d+i)*stride_r],t,2*N-k);
  }
}
