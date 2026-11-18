//TODO: no divmont in first forward level of interleaved ntt
//compare to zero / add or sub p

#include <stdint.h>
#include <immintrin.h>
#include "data.h"
#include "poly.h"

#define _mm512_moveldup_epi32(f) _mm512_castps_si512(_mm512_moveldup_ps(_mm512_castsi512_ps(f)))
#pragma GCC diagnostic ignored "-Wunused-label"

static inline __m512i mulmod(const __m512i a, const __m512i b, const __m512i b_pinv, const __m512i p) {
  __m512i r,t;

  t = _mm512_mullo_epi16(a,b_pinv);
  r = _mm512_mulhi_epi16(a,b);
  t = _mm512_mulhi_epi16(t,p);
  r = _mm512_sub_epi16(r,t);
  return r;
}

static inline __m512i divmont(const __m512i a, const __m512i p, const __m512i pinv) {
  __m512i r,t;

  t = _mm512_mullo_epi16(a,pinv);
  r = _mm512_srai_epi16(a,15);
  t = _mm512_mulhi_epi16(t,p);
  r = _mm512_sub_epi16(r,t);
  return r;
}

/* These kernels are restricted to the fixed 256-coefficient transforms:
 * their second factors are bounded twiddle/scaling entries in data*.c.
 * The general interleaved transforms retain the original kernels below. */
#if defined(__aarch64__) && !defined(SIMDE_NO_NATIVE)
#include "arm_montgomery.h"
static inline __m512i ntt_mulmod(__m512i a,__m512i b,__m512i b_pinv,__m512i p) {
  simde__m512i_private aa=simde__m512i_to_private(a),bb=simde__m512i_to_private(b);
  simde__m512i_private bi=simde__m512i_to_private(b_pinv),pp=simde__m512i_to_private(p),out;
  for(size_t i=0;i<4;i++)
    out.m128i_private[i].neon_i16=quil_arm_mulmod(aa.m128i_private[i].neon_i16,
        bb.m128i_private[i].neon_i16,bi.m128i_private[i].neon_i16,pp.m128i_private[i].neon_i16);
  return simde__m512i_from_private(out);
}
static inline __m512i ntt_divmont(__m512i a,__m512i p,__m512i pinv) {
  simde__m512i_private aa=simde__m512i_to_private(a),pp=simde__m512i_to_private(p);
  simde__m512i_private pi=simde__m512i_to_private(pinv),out;
  for(size_t i=0;i<4;i++)
    out.m128i_private[i].neon_i16=quil_arm_divmont(aa.m128i_private[i].neon_i16,
        pp.m128i_private[i].neon_i16,pi.m128i_private[i].neon_i16);
  return simde__m512i_from_private(out);
}
#else
#define ntt_mulmod mulmod
#define ntt_divmont divmont
#endif

void poly_ntt(poly r, const poly a, const pdata prime) {
  size_t i;
  __m512i f[N/32],g[N/32];
  __m512i zeta,zeta_pinv;
  __m512i permwidx;
  __m512i t;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

load:
  for(i=0;i<N/32;i++)
    f[i] = _mm512_load_si512(&a->v[i]);

level0:
  zeta = _mm512_set1_epi16(prime->i);
  zeta_pinv = _mm512_set1_epi16(prime->i_pinv);
  for(i=0;i<N/64;i++) {
    t = ntt_mulmod(f[N/64+i],zeta,zeta_pinv,p);

    f[N/64+i] = _mm512_sub_epi16(f[i],t);
    f[i] = _mm512_add_epi16(f[i],t);

    g[2*i+0] = _mm512_shuffle_i64x2(f[i],f[N/64+i],0x44);
    g[2*i+1] = _mm512_shuffle_i64x2(f[i],f[N/64+i],0xEE);
  }

level1:
  zeta = _mm512_castsi128_si512(_mm_loadl_epi64((__m128i*)&prime->zetas->c[2]));
  zeta_pinv = _mm512_castsi128_si512(_mm_loadl_epi64((__m128i*)&prime->zetas_pinv->c[2]));
  permwidx = _mm512_set_epi16(1,1,1,1,1,1,1,1,
                              1,1,1,1,1,1,1,1,
                              0,0,0,0,0,0,0,0,
                              0,0,0,0,0,0,0,0);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=0;i<N/64;i++) {
    t = ntt_mulmod(g[N/64+i],zeta,zeta_pinv,p);
    g[i] = ntt_divmont(g[i],p,pinv);

    g[N/64+i] = _mm512_sub_epi16(g[i],t);
    g[i] = _mm512_add_epi16(g[i],t);

    f[2*i+0] = _mm512_shuffle_i64x2(g[i],g[N/64+i],0x88);
    f[2*i+1] = _mm512_shuffle_i64x2(g[i],g[N/64+i],0xDD);
  }

level2:
  zeta = _mm512_castsi128_si512(_mm_loadl_epi64((__m128i*)&prime->zetas->c[4]));
  zeta_pinv = _mm512_castsi128_si512(_mm_loadl_epi64((__m128i*)&prime->zetas_pinv->c[4]));
  permwidx = _mm512_set_epi16(3,3,3,3,3,3,3,3,
                              1,1,1,1,1,1,1,1,
                              2,2,2,2,2,2,2,2,
                              0,0,0,0,0,0,0,0);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=0;i<N/64;i++) {
    t = ntt_mulmod(f[N/64+i],zeta,zeta_pinv,p);
    f[i] = ntt_divmont(f[i],p,pinv);

    f[N/64+i] = _mm512_sub_epi16(f[i],t);
    f[i] = _mm512_add_epi16(f[i],t);

    g[2*i+0] = _mm512_unpacklo_epi64(f[i],f[N/64+i]);
    g[2*i+1] = _mm512_unpackhi_epi64(f[i],f[N/64+i]);
  }

level3:
  zeta = _mm512_castsi128_si512(_mm_load_si128((__m128i*)&prime->zetas->c[8]));
  zeta_pinv = _mm512_castsi128_si512(_mm_load_si128((__m128i*)&prime->zetas_pinv->c[8]));
  permwidx = _mm512_set_epi16(7,7,7,7,6,6,6,6,
                              3,3,3,3,2,2,2,2,
                              5,5,5,5,4,4,4,4,
                              1,1,1,1,0,0,0,0);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=0;i<N/64;i++) {
    t = ntt_mulmod(g[N/64+i],zeta,zeta_pinv,p);
    g[i] = ntt_divmont(g[i],p,pinv);

    g[N/64+i] = _mm512_sub_epi16(g[i],t);
    g[i] = _mm512_add_epi16(g[i],t);

    t = _mm512_moveldup_epi32(g[N/64+i]);
    f[2*i+0] = _mm512_mask_blend_epi32(0xAAAA,g[i],t);
    t = _mm512_srli_epi64(g[i],32);
    f[2*i+1] = _mm512_mask_blend_epi32(0xAAAA,t,g[N/64+i]);
  }

level4:
  zeta = _mm512_castsi256_si512(_mm256_load_si256((__m256i*)&prime->zetas->c[16]));
  zeta_pinv = _mm512_castsi256_si512(_mm256_load_si256((__m256i*)&prime->zetas_pinv->c[16]));
  permwidx = _mm512_set_epi16(15,15,14,14,13,13,12,12,
                               7, 7, 6, 6, 5, 5, 4, 4,
                              11,11,10,10, 9, 9, 8, 8,
                               3, 3, 2, 2, 1, 1, 0, 0);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=0;i<N/64;i++) {
    t = ntt_mulmod(f[N/64+i],zeta,zeta_pinv,p);
    f[i] = ntt_divmont(f[i],p,pinv);

    f[N/64+i] = _mm512_sub_epi16(f[i],t);
    f[i] = _mm512_add_epi16(f[i],t);

    t = _mm512_slli_epi32(f[N/64+i],16);
    g[2*i+0] = _mm512_mask_blend_epi16(0xAAAAAAAA,f[i],t);
    t = _mm512_srli_epi32(f[i],16);
    g[2*i+1] = _mm512_mask_blend_epi16(0xAAAAAAAA,t,f[N/64+i]);
  }

level5:
  zeta = _mm512_load_si512((__m512i*)&prime->zetas->c[32]);
  zeta_pinv = _mm512_load_si512((__m512i*)&prime->zetas_pinv->c[32]);
  zeta = _mm512_shuffle_i64x2(zeta,zeta,0xD8);
  zeta_pinv = _mm512_shuffle_i64x2(zeta_pinv,zeta_pinv,0xD8);
  for(i=0;i<N/64;i++) {
    t = ntt_mulmod(g[N/64+i],zeta,zeta_pinv,p);
    g[i] = ntt_divmont(g[i],p,pinv);

    g[N/64+i] = _mm512_sub_epi16(g[i],t);
    g[i] = _mm512_add_epi16(g[i],t);
  }

#if N >= 128
level6:
  zeta = _mm512_load_si512((__m512i*)&prime->zetas->c[64]);
  zeta_pinv = _mm512_load_si512((__m512i*)&prime->zetas_pinv->c[64]);
  for(i=0;i<N/128;i++) {
    t = ntt_mulmod(g[N/128+i],zeta,zeta_pinv,p);
    g[i] = ntt_divmont(g[i],p,pinv);

    g[N/128+i] = _mm512_sub_epi16(g[i],t);
    g[i] = _mm512_add_epi16(g[i],t);
  }
  zeta = _mm512_load_si512((__m512i*)&prime->zetas->c[96]);
  zeta_pinv = _mm512_load_si512((__m512i*)&prime->zetas_pinv->c[96]);
  for(i=0;i<N/128;i++) {
    t = ntt_mulmod(g[N/64+N/128+i],zeta,zeta_pinv,p);
    g[N/64+i] = ntt_divmont(g[N/64+i],p,pinv);

    g[N/64+N/128+i] = _mm512_sub_epi16(g[N/64+i],t);
    g[N/64+i] = _mm512_add_epi16(g[N/64+i],t);
  }
#endif

#if N >= 256
level7:
  for(i=0;i<4;i++) {
    zeta = _mm512_load_si512((__m512i*)&prime->zetas->c[128+32*i]);
    zeta_pinv = _mm512_load_si512((__m512i*)&prime->zetas_pinv->c[128+32*i]);
    g[2*i+0] = ntt_divmont(g[2*i+0],p,pinv);
    t = ntt_mulmod(g[2*i+1],zeta,zeta_pinv,p);
    g[2*i+1] = _mm512_sub_epi16(g[2*i+0],t);
    g[2*i+0] = _mm512_add_epi16(g[2*i+0],t);
  }
#endif

scale:
  zeta = _mm512_set1_epi16(prime->f);
  zeta_pinv = _mm512_set1_epi16(prime->f_pinv);
  for(i=0;i<N/32;i++) {
    g[i] = ntt_mulmod(g[i],zeta,zeta_pinv,p);
    _mm512_store_si512(&r->v[i],g[i]);
  }
}

void poly_invntt(poly r, const poly a, const pdata prime) {
  size_t i;
  __m512i t;
  __m512i f[N/32],g[N/32];
  __m512i zeta,zeta_pinv;
  __m512i permwidx = _mm512_set_epi16( 0, 1, 2, 3, 4, 5, 6, 7,
                                       8, 9,10,11,12,13,14,15,
                                      16,17,18,19,20,21,22,23,
                                      24,25,26,27,28,29,30,31);
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

load:
  for(i=0;i<N/32;i++)
    f[i] = _mm512_load_si512(&a->v[i]);

#if N >= 256
level7:
  for(i=0;i<4;i++) {
    zeta = _mm512_load_si512((__m512i*)&prime->zetas->c[224-32*i]);
    zeta_pinv = _mm512_load_si512((__m512i*)&prime->zetas_pinv->c[224-32*i]);
    zeta = _mm512_permutexvar_epi16(permwidx,zeta);
    zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
    t = _mm512_add_epi16(f[2*i+0],f[2*i+1]);
    f[2*i+1] = _mm512_sub_epi16(f[2*i+1],f[2*i+0]);
    f[2*i+0] = ntt_divmont(t,p,pinv);
    f[2*i+1] = ntt_mulmod(f[2*i+1],zeta,zeta_pinv,p);
  }
#endif

#if N >= 128
level6:
  zeta = _mm512_load_si512((__m512i*)&prime->zetas->c[96]);
  zeta_pinv = _mm512_load_si512((__m512i*)&prime->zetas_pinv->c[96]);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=0;i<N/128;i++) {
    t = _mm512_add_epi16(f[i],f[N/128+i]);
    f[N/128+i] = _mm512_sub_epi16(f[N/128+i],f[i]);

    f[i] = ntt_divmont(t,p,pinv);
    f[N/128+i] = ntt_mulmod(f[N/128+i],zeta,zeta_pinv,p);
  }
  zeta = _mm512_load_si512((__m512i*)&prime->zetas->c[64]);
  zeta_pinv = _mm512_load_si512((__m512i*)&prime->zetas_pinv->c[64]);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=N/64;i<N/64+N/128;i++) {
    t = _mm512_add_epi16(f[i],f[N/128+i]);
    f[N/128+i] = _mm512_sub_epi16(f[N/128+i],f[i]);

    f[i] = ntt_divmont(t,p,pinv);
    f[N/128+i] = ntt_mulmod(f[N/128+i],zeta,zeta_pinv,p);
  }
#endif

level5:
  zeta = _mm512_load_si512((__m512i*)&prime->zetas->c[32]);
  zeta_pinv = _mm512_load_si512((__m512i*)&prime->zetas_pinv->c[32]);
  permwidx = _mm512_shuffle_i64x2(permwidx,permwidx,0xD8);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=0;i<N/64;i++) {
    t = _mm512_add_epi16(f[i],f[N/64+i]);
    f[N/64+i] = _mm512_sub_epi16(f[N/64+i],f[i]);

    f[i] = ntt_divmont(t,p,pinv);
    f[N/64+i] = ntt_mulmod(f[N/64+i],zeta,zeta_pinv,p);
  }

level4:
  zeta = _mm512_castsi256_si512(_mm256_load_si256((__m256i*)&prime->zetas->c[16]));
  zeta_pinv = _mm512_castsi256_si512(_mm256_load_si256((__m256i*)&prime->zetas_pinv->c[16]));
  permwidx = _mm512_set_epi16( 0, 0, 1, 1, 2, 2, 3, 3,
                               8, 8, 9, 9,10,10,11,11,
                               4, 4, 5, 5, 6, 6, 7, 7,
                              12,12,13,13,14,14,15,15);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=0;i<N/64;i++) {
    t = _mm512_slli_epi32(f[2*i+1],16);
    g[i] = _mm512_mask_blend_epi16(0xAAAAAAAA,f[2*i+0],t);
    t = _mm512_srli_epi32(f[2*i+0],16);
    g[N/64+i] = _mm512_mask_blend_epi16(0xAAAAAAAA,t,f[2*i+1]);

    t = _mm512_add_epi16(g[i],g[N/64+i]);
    g[N/64+i] = _mm512_sub_epi16(g[N/64+i],g[i]);

    g[i] = ntt_divmont(t,p,pinv);
    g[N/64+i] = ntt_mulmod(g[N/64+i],zeta,zeta_pinv,p);
  }

level3:
  zeta = _mm512_castsi128_si512(_mm_load_si128((__m128i*)&prime->zetas->c[8]));
  zeta_pinv = _mm512_castsi128_si512(_mm_load_si128((__m128i*)&prime->zetas_pinv->c[8]));
  permwidx = _mm512_set_epi16(0,0,0,0,1,1,1,1,
                              4,4,4,4,5,5,5,5,
                              2,2,2,2,3,3,3,3,
                              6,6,6,6,7,7,7,7);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=0;i<N/64;i++) {
    t = _mm512_moveldup_epi32(g[2*i+1]);
    f[i] = _mm512_mask_blend_epi32(0xAAAA,g[2*i+0],t);
    t = _mm512_srli_epi64(g[2*i+0],32);
    f[N/64+i] = _mm512_mask_blend_epi32(0xAAAA,t,g[2*i+1]);

    t = _mm512_add_epi16(f[i],f[N/64+i]);
    f[N/64+i] = _mm512_sub_epi16(f[N/64+i],f[i]);

    f[i] = ntt_divmont(t,p,pinv);
    f[N/64+i] = ntt_mulmod(f[N/64+i],zeta,zeta_pinv,p);
  }

level2:
  zeta = _mm512_castsi128_si512(_mm_loadl_epi64((__m128i*)&prime->zetas->c[4]));
  zeta_pinv = _mm512_castsi128_si512(_mm_loadl_epi64((__m128i*)&prime->zetas_pinv->c[4]));
  permwidx = _mm512_set_epi16(0,0,0,0,0,0,0,0,
                              2,2,2,2,2,2,2,2,
                              1,1,1,1,1,1,1,1,
                              3,3,3,3,3,3,3,3);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=0;i<N/64;i++) {
    g[i] = _mm512_unpacklo_epi64(f[2*i+0],f[2*i+1]);
    g[N/64+i] = _mm512_unpackhi_epi64(f[2*i+0],f[2*i+1]);

    t = _mm512_add_epi16(g[i],g[N/64+i]);
    g[N/64+i] = _mm512_sub_epi16(g[N/64+i],g[i]);

    g[i] = ntt_divmont(t,p,pinv);
    g[N/64+i] = ntt_mulmod(g[N/64+i],zeta,zeta_pinv,p);
  }

level1:
  zeta = _mm512_castsi128_si512(_mm_loadl_epi64((__m128i*)&prime->zetas->c[2]));
  zeta_pinv = _mm512_castsi128_si512(_mm_loadl_epi64((__m128i*)&prime->zetas_pinv->c[2]));
  permwidx = _mm512_set_epi16(0,0,0,0,0,0,0,0,
                              0,0,0,0,0,0,0,0,
                              1,1,1,1,1,1,1,1,
                              1,1,1,1,1,1,1,1);
  zeta = _mm512_permutexvar_epi16(permwidx,zeta);
  zeta_pinv = _mm512_permutexvar_epi16(permwidx,zeta_pinv);
  for(i=0;i<N/64;i++) {
    f[i] = _mm512_shuffle_i64x2(g[2*i+0],g[2*i+1],0x44);
    f[N/64+i] = _mm512_shuffle_i64x2(g[2*i+0],g[2*i+1],0xEE);
    f[i] = _mm512_shuffle_i64x2(f[i],f[i],0xD8);
    f[N/64+i] = _mm512_shuffle_i64x2(f[N/64+i],f[N/64+i],0xD8);

    t = _mm512_add_epi16(f[i],f[N/64+i]);
    f[N/64+i] = _mm512_sub_epi16(f[N/64+i],f[i]);

    f[i] = ntt_divmont(t,p,pinv);
    f[N/64+i] = ntt_mulmod(f[N/64+i],zeta,zeta_pinv,p);
  }

level0:
  zeta = _mm512_set1_epi16(prime->zetas->c[1]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[1]);
  for(i=0;i<N/64;i++) {
    g[i] = _mm512_shuffle_i64x2(f[2*i+0],f[2*i+1],0x44);
    g[N/64+i] = _mm512_shuffle_i64x2(f[2*i+0],f[2*i+1],0xEE);

    t = _mm512_add_epi16(g[i],g[N/64+i]);
    g[N/64+i] = _mm512_sub_epi16(g[N/64+i],g[i]);

    g[i] = ntt_divmont(t,p,pinv);
    g[N/64+i] = ntt_mulmod(g[N/64+i],zeta,zeta_pinv,p);
  }

store:
  for(i=0;i<N/32;i++)
    _mm512_store_si512(&r->v[i],g[i]);
}

void poly_nttunpack(poly r, const pdata prime) {
  size_t i;
  __m512i f[N/32],g[N/32];
  __m512i t;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

  for(i=0;i<N/32;i++) {
    f[i] = _mm512_load_si512(&r->v[i]);
    f[i] = divmont(f[i],p,pinv);
  }

  for(i=0;i<N/64;i++) {
    t = _mm512_slli_epi32(f[2*i+1],16);
    g[i] = _mm512_mask_blend_epi16(0xAAAAAAAA,f[2*i+0],t);
    t = _mm512_srli_epi32(f[2*i+0],16);
    g[N/64+i] = _mm512_mask_blend_epi16(0xAAAAAAAA,t,f[2*i+1]);
  }

  for(i=0;i<N/64;i++) {
    t = _mm512_moveldup_epi32(g[2*i+1]);
    f[i] = _mm512_mask_blend_epi32(0xAAAA,g[2*i+0],t);
    t = _mm512_srli_epi64(g[2*i+0],32);
    f[N/64+i] = _mm512_mask_blend_epi32(0xAAAA,t,g[2*i+1]);
  }

  for(i=0;i<N/64;i++) {
    g[i] = _mm512_unpacklo_epi64(f[2*i+0],f[2*i+1]);
    g[N/64+i] = _mm512_unpackhi_epi64(f[2*i+0],f[2*i+1]);
  }

  for(i=0;i<N/64;i++) {
    f[i] = _mm512_shuffle_i64x2(g[2*i+0],g[2*i+1],0x44);
    f[N/64+i] = _mm512_shuffle_i64x2(g[2*i+0],g[2*i+1],0xEE);
    f[i] = _mm512_shuffle_i64x2(f[i],f[i],0xD8);
    f[N/64+i] = _mm512_shuffle_i64x2(f[N/64+i],f[N/64+i],0xD8);
  }

  for(i=0;i<N/64;i++) {
    g[i] = _mm512_shuffle_i64x2(f[2*i+0],f[2*i+1],0x44);
    g[N/64+i] = _mm512_shuffle_i64x2(f[2*i+0],f[2*i+1],0xEE);
  }

  for(i=0;i<N/32;i++)
    _mm512_store_si512(&r->v[i],g[i]);
}

static inline void ctbttrfly(__m512i *f, size_t len, __m512i zeta, __m512i zeta_pinv, __m512i p, __m512i pinv) {
  size_t j;
  __m512i t;

  for(j=0;j<len;j++) {
    t = mulmod(f[j+len],zeta,zeta_pinv,p);
    f[j] = divmont(f[j],p,pinv);
    f[j+len] = _mm512_sub_epi16(f[j],t);
    f[j] = _mm512_add_epi16(f[j],t);
  }
}

static inline void gsbttrfly(__m512i *f, size_t len, __m512i zeta, __m512i zeta_pinv, __m512i p, __m512i pinv) {
  size_t j;
  __m512i t;

  for(j=0;j<len;j++) {
    t = _mm512_sub_epi16(f[j+len],f[j]);
    f[j] = _mm512_add_epi16(f[j],f[j+len]);
    f[j+len] = mulmod(t,zeta,zeta_pinv,p);
    f[j] = divmont(f[j],p,pinv);
  }
}

static inline void ntt_interleaved32_levels1t4(__m512i *r, const __m512i *a,
                                               ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime)
{
  size_t i,j,l;
  __m512i f[16];
  __m512i zeta[8],zeta_pinv[8];
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

  for(i=0;i<8;i++) {
    zeta[i] = _mm512_set1_epi16(prime->zetas->c[i]);
    zeta_pinv[i] = _mm512_set1_epi16(prime->zetas_pinv->c[i]);
  }
  for(i=0;i<len/16;i++) {
    for(j=0;j<16;j++)
      f[j] = _mm512_load_si512(&a[stride_a*(len/16*j+i)]);
    for(l=8;l>=1;l/=2)
      for(j=0;j<8/l;j++)
        ctbttrfly(&f[j*2*l],l,zeta[j],zeta_pinv[j],p,pinv);
    for(j=0;j<16;j++)
      _mm512_store_si512(&r[stride_r*(len/16*j+i)],f[j]);
  }
}

static inline void ntt_interleaved32_levels1t4_negacyclic(__m512i *r, const __m512i *a,
                                                          ssize_t stride_r, ssize_t stride_a, size_t len,
                                                          const pdata prime)
{
  size_t i,j,k,l;
  __m512i f[16];
  __m512i zeta[15],zeta_pinv[15];
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

  for(i=0;i<15;i++) {
    zeta[i] = _mm512_set1_epi16(prime->zetas->c[1+i]);
    zeta_pinv[i] = _mm512_set1_epi16(prime->zetas_pinv->c[1+i]);
  }
  for(i=0;i<len/16;i++) {
    for(j=0;j<16;j++)
      f[j] = _mm512_load_si512(&a[stride_a*(len/16*j+i)]);
    k = 0;
    for(l=8;l>=1;l/=2) {
      for(j=0;j<16;j+=2*l) {
        ctbttrfly(&f[j],l,zeta[k],zeta_pinv[k],p,pinv);
        k += 1;
      }
    }
    for(j=0;j<16;j++)
      _mm512_store_si512(&r[stride_r*(len/16*j+i)],f[j]);
  }
}

static inline void ntt_interleaved32_levels5t8(__m512i *r, ssize_t stride, size_t len, const pdata prime) {
  size_t i,j;
  __m512i f[16];
  __m512i zeta,zeta_pinv;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);
  const __m512i s = _mm512_set1_epi16(pow_simple(2*len,16,prime));
  const __m512i s_pinv = _mm512_mullo_epi16(s,pinv);
  const size_t idx[] = {0,1,2,3,8,9,10,11,4,5,6,7,12,13,14,15};

  for(i=0;i<len/16;i++) {
    for(j=0;j<16;j++)
      f[j] = _mm512_load_si512(&r[stride*(16*i+j)]);

level5:
    if(len >= 256) {
      zeta = _mm512_set1_epi16(prime->zetas->c[i]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[i]);
      ctbttrfly(&f[0],8,zeta,zeta_pinv,p,pinv);
    }

level6:
    if(len >= 128) {
      for(j=0;j<2;j++) {
        zeta = _mm512_set1_epi16(prime->zetas->c[2*i+j]);
        zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[2*i+j]);
        ctbttrfly(&f[8*j],4,zeta,zeta_pinv,p,pinv);
      }
    }

level7:
    if(len >= 64) {
      for(j=0;j<4;j++) {
        zeta = _mm512_set1_epi16(prime->zetas->c[4*i+j]);
        zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[4*i+j]);
        ctbttrfly(&f[4*j],2,zeta,zeta_pinv,p,pinv);
      }
    }

level8:
    if(len >= 32 && i<8) {
      for(j=0;j<8;j++) {
        zeta = _mm512_set1_epi16(prime->zetas->c[8*i+j]);
        zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[8*i+j]);
        ctbttrfly(&f[2*j],1,zeta,zeta_pinv,p,pinv);
      }
    }
    else if(len >= 32) {
      zeta = _mm512_set1_epi16(prime->zetas->c[64+2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[64+2*idx[2*i-16]]);
      ctbttrfly(&f[0],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[96+2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[96+2*idx[2*i-16]]);
      ctbttrfly(&f[2],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[65+2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[65+2*idx[2*i-16]]);
      ctbttrfly(&f[4],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[97+2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[97+2*idx[2*i-16]]);
      ctbttrfly(&f[6],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[66+2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[66+2*idx[2*i-16]]);
      ctbttrfly(&f[8],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[98+2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[98+2*idx[2*i-16]]);
      ctbttrfly(&f[10],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[67+2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[67+2*idx[2*i-16]]);
      ctbttrfly(&f[12],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[99+2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[99+2*idx[2*i-16]]);
      ctbttrfly(&f[14],1,zeta,zeta_pinv,p,pinv);
    }

scale:
    for(j=0;j<16;j++)
      f[j] = mulmod(f[j],s,s_pinv,p);

    for(j=0;j<16;j++)
      _mm512_store_si512(&r[stride*(16*i+j)],f[j]);
  }
}

static inline void ntt_interleaved32_levels5t8_negacyclic(__m512i *r, ssize_t stride, size_t len, const pdata prime) {
  size_t i,j;
  __m512i f[16];
  __m512i zeta,zeta_pinv;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);
  const __m512i s = _mm512_set1_epi16(pow_simple(2*len,16,prime));
  const __m512i s_pinv = _mm512_mullo_epi16(s,pinv);
  const size_t idx[] = {0,1,2,3,8,9,10,11,4,5,6,7,12,13,14,15};

  for(i=0;i<len/16;i++) {
    for(j=0;j<16;j++)
      f[j] = _mm512_load_si512(&r[stride*(16*i+j)]);

level5:
    if(len >= 256) {
      zeta = _mm512_set1_epi16(prime->zetas->c[len/16+i]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[len/16+i]);
      ctbttrfly(&f[0],8,zeta,zeta_pinv,p,pinv);
    }

level6:
    if(len >= 128) {
      for(j=0;j<2;j++) {
        zeta = _mm512_set1_epi16(prime->zetas->c[len/8+2*i+j]);
        zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[len/8+2*i+j]);
        ctbttrfly(&f[8*j],4,zeta,zeta_pinv,p,pinv);
      }
    }

level7:
    if(len >= 64 && len <= 128) {
      for(j=0;j<4;j++) {
        zeta = _mm512_set1_epi16(prime->zetas->c[len/4+4*i+j]);
        zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[len/4+4*i+j]);
        ctbttrfly(&f[4*j],2,zeta,zeta_pinv,p,pinv);
      }
    }
    else if(len >= 256) {
      zeta = _mm512_set1_epi16(prime->zetas->c[64+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[64+2*idx[i]]);
      ctbttrfly(&f[0],2,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[96+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[96+2*idx[i]]);
      ctbttrfly(&f[4],2,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[65+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[65+2*idx[i]]);
      ctbttrfly(&f[8],2,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[97+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[97+2*idx[i]]);
      ctbttrfly(&f[12],2,zeta,zeta_pinv,p,pinv);
    }

level8:
    if(len >= 32 && len <= 64) {
      for(j=0;j<8;j++) {
        zeta = _mm512_set1_epi16(prime->zetas->c[len/2+8*i+j]);
        zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[len/2+8*i+j]);
        ctbttrfly(&f[2*j],1,zeta,zeta_pinv,p,pinv);
      }
    }
    else if(len == 128) {
      zeta = _mm512_set1_epi16(prime->zetas->c[64+2*idx[2*i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[64+2*idx[2*i]]);
      ctbttrfly(&f[0],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[96+2*idx[2*i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[96+2*idx[2*i]]);
      ctbttrfly(&f[2],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[65+2*idx[2*i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[65+2*idx[2*i]]);
      ctbttrfly(&f[4],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[97+2*idx[2*i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[97+2*idx[2*i]]);
      ctbttrfly(&f[6],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[66+2*idx[2*i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[66+2*idx[2*i]]);
      ctbttrfly(&f[8],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[98+2*idx[2*i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[98+2*idx[2*i]]);
      ctbttrfly(&f[10],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[67+2*idx[2*i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[67+2*idx[2*i]]);
      ctbttrfly(&f[12],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[99+2*idx[2*i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[99+2*idx[2*i]]);
      ctbttrfly(&f[14],1,zeta,zeta_pinv,p,pinv);
    }
    else if(len >= 256) {
      zeta = _mm512_set1_epi16(prime->zetas->c[128+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[128+2*idx[i]]);
      ctbttrfly(&f[0],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[160+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[160+2*idx[i]]);
      ctbttrfly(&f[2],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[192+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[192+2*idx[i]]);
      ctbttrfly(&f[4],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[224+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[224+2*idx[i]]);
      ctbttrfly(&f[6],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[129+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[129+2*idx[i]]);
      ctbttrfly(&f[8],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[161+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[161+2*idx[i]]);
      ctbttrfly(&f[10],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[193+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[193+2*idx[i]]);
      ctbttrfly(&f[12],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[225+2*idx[i]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[225+2*idx[i]]);
      ctbttrfly(&f[14],1,zeta,zeta_pinv,p,pinv);
    }

scale:
    for(j=0;j<16;j++)
      f[j] = mulmod(f[j],s,s_pinv,p);

    for(j=0;j<16;j++)
      _mm512_store_si512(&r[stride*(16*i+j)],f[j]);
  }
}

static inline size_t invidx(size_t i) {
  const size_t idx[] = {0,2,1,3};

       if(i<  1) return 0;
  else if(i<  2) return 1;
  else if(i<  4) return 5-i;
  else if(i<  8) return 11-i;
  else if(i< 16) return 23-i;
  else if(i< 32) return 47-i;
  else if(i< 64) return 95-i;
  else if(i<128) return 127-32*(i%2)-8*idx[(i-64)/16]-i/2%8;
  else           return 255-32*(i%4)-8*idx[(i-128)/32]-i/4%8;
}

static inline void invntt_interleaved32_levels8t5(__m512i *r, const __m512i *a,
                                                  ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime)
{
  size_t i,j;
  __m512i f[16];
  __m512i zeta,zeta_pinv;
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);
  const size_t idx[] = {0,1,2,3,8,9,10,11,4,5,6,7,12,13,14,15};

  for(j=0;j<16;j++)
    f[j] = _mm512_load_si512(&a[stride_a*j]);

level8_0:
  zeta = _mm512_set1_epi16(-prime->zetas->c[0]);
  zeta_pinv = _mm512_set1_epi16(-prime->zetas_pinv->c[0]);
  gsbttrfly(&f[0],1,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[1]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[1]);
  gsbttrfly(&f[2],1,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[3]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[3]);
  gsbttrfly(&f[4],1,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[2]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[2]);
  gsbttrfly(&f[6],1,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[7]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[7]);
  gsbttrfly(&f[8],1,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[6]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[6]);
  gsbttrfly(&f[10],1,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[5]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[5]);
  gsbttrfly(&f[12],1,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[4]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[4]);
  gsbttrfly(&f[14],1,zeta,zeta_pinv,p,pinv);

level7_0:
  zeta = _mm512_set1_epi16(-prime->zetas->c[0]);
  zeta_pinv = _mm512_set1_epi16(-prime->zetas_pinv->c[0]);
  gsbttrfly(&f[0],2,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[1]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[1]);
  gsbttrfly(&f[4],2,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[3]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[3]);
  gsbttrfly(&f[8],2,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[2]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[2]);
  gsbttrfly(&f[12],2,zeta,zeta_pinv,p,pinv);

level6_0:
  zeta = _mm512_set1_epi16(-prime->zetas->c[0]);
  zeta_pinv = _mm512_set1_epi16(-prime->zetas_pinv->c[0]);
  gsbttrfly(&f[0],4,zeta,zeta_pinv,p,pinv);
  zeta = _mm512_set1_epi16(prime->zetas->c[1]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[1]);
  gsbttrfly(&f[8],4,zeta,zeta_pinv,p,pinv);

level5_0:
  zeta = _mm512_set1_epi16(-prime->zetas->c[0]);
  zeta_pinv = _mm512_set1_epi16(-prime->zetas_pinv->c[0]);
  gsbttrfly(&f[0],8,zeta,zeta_pinv,p,pinv);

  for(j=0;j<16;j++)
    _mm512_store_si512(&r[stride_r*j],f[j]);

  for(j=0;j<16;j++)
    f[j] = _mm512_load_si512(&r[stride_r*(16+j)]);

level8_1:
  for(j=0;j<8;j++) {
    zeta = _mm512_set1_epi16(prime->zetas->c[15-j]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[15-j]);
    gsbttrfly(&f[2*j],1,zeta,zeta_pinv,p,pinv);
  }

level7_1:
  for(j=0;j<4;j++) {
    zeta = _mm512_set1_epi16(prime->zetas->c[7-j]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[7-j]);
    gsbttrfly(&f[4*j],2,zeta,zeta_pinv,p,pinv);
  }

level6_1:
  for(j=0;j<2;j++) {
    zeta = _mm512_set1_epi16(prime->zetas->c[3-j]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[3-j]);
    gsbttrfly(&f[8*j],4,zeta,zeta_pinv,p,pinv);
  }

level5_1:
  zeta = _mm512_set1_epi16(prime->zetas->c[1]);
  zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[1]);
  gsbttrfly(&f[0],8,zeta,zeta_pinv,p,pinv);

  for(j=0;j<16;j++)
    _mm512_store_si512(&r[stride_r*(16+j)],f[j]);

  if(len<=32) return;

  for(i=2;i<4;i++) {
    for(j=0;j<16;j++)
      f[j] = _mm512_load_si512(&r[stride_r*(16*i+j)]);

level8_2t3:
    for(j=0;j<8;j++) {
      zeta = _mm512_set1_epi16(prime->zetas->c[47-8*i-j]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[47-8*i-j]);
      gsbttrfly(&f[2*j],1,zeta,zeta_pinv,p,pinv);
    }

level7_2t3:
    for(j=0;j<4;j++) {
      zeta = _mm512_set1_epi16(prime->zetas->c[23-4*i-j]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[23-4*i-j]);
      gsbttrfly(&f[4*j],2,zeta,zeta_pinv,p,pinv);
    }

level6_2t3:
    for(j=0;j<2;j++) {
      zeta = _mm512_set1_epi16(prime->zetas->c[11-2*i-j]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[11-2*i-j]);
      gsbttrfly(&f[8*j],4,zeta,zeta_pinv,p,pinv);
    }

level5_2t3:
    zeta = _mm512_set1_epi16(prime->zetas->c[5-i]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[5-i]);
    gsbttrfly(&f[0],8,zeta,zeta_pinv,p,pinv);

    for(j=0;j<16;j++)
      _mm512_store_si512(&r[stride_r*(16*i+j)],f[j]);
  }

  if(len<=64) return;

  for(i=4;i<8;i++) {
    for(j=0;j<16;j++)
      f[j] = _mm512_load_si512(&r[stride_r*(16*i+j)]);

level8_4t7:
    for(j=0;j<8;j++) {
      zeta = _mm512_set1_epi16(prime->zetas->c[95-8*i-j]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[95-8*i-j]);
      gsbttrfly(&f[2*j],1,zeta,zeta_pinv,p,pinv);
    }

level7_4t7:
    for(j=0;j<4;j++) {
      zeta = _mm512_set1_epi16(prime->zetas->c[47-4*i-j]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[47-4*i-j]);
      gsbttrfly(&f[4*j],2,zeta,zeta_pinv,p,pinv);
    }

level6_4t7:
    for(j=0;j<2;j++) {
      zeta = _mm512_set1_epi16(prime->zetas->c[23-2*i-j]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[23-2*i-j]);
      gsbttrfly(&f[8*j],4,zeta,zeta_pinv,p,pinv);
    }

level5_4t7:
    zeta = _mm512_set1_epi16(prime->zetas->c[11-i]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[11-i]);
    gsbttrfly(&f[0],8,zeta,zeta_pinv,p,pinv);

    for(j=0;j<16;j++)
      _mm512_store_si512(&r[stride_r*(16*i+j)],f[j]);
  }

  if(len<=128) return;

  for(i=8;i<16;i++) {
    for(j=0;j<16;j++)
      f[j] = _mm512_load_si512(&r[stride_r*(16*i+j)]);

level8_8t15:
      zeta = _mm512_set1_epi16(prime->zetas->c[127-2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[127-2*idx[2*i-16]]);
      gsbttrfly(&f[0],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[95-2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[95-2*idx[2*i-16]]);
      gsbttrfly(&f[2],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[126-2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[126-2*idx[2*i-16]]);
      gsbttrfly(&f[4],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[94-2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[94-2*idx[2*i-16]]);
      gsbttrfly(&f[6],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[125-2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[125-2*idx[2*i-16]]);
      gsbttrfly(&f[8],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[93-2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[93-2*idx[2*i-16]]);
      gsbttrfly(&f[10],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[124-2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[124-2*idx[2*i-16]]);
      gsbttrfly(&f[12],1,zeta,zeta_pinv,p,pinv);
      zeta = _mm512_set1_epi16(prime->zetas->c[92-2*idx[2*i-16]]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[92-2*idx[2*i-16]]);
      gsbttrfly(&f[14],1,zeta,zeta_pinv,p,pinv);

level7_8t15:
    for(j=0;j<4;j++) {
      zeta = _mm512_set1_epi16(prime->zetas->c[95-4*i-j]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[95-4*i-j]);
      gsbttrfly(&f[4*j],2,zeta,zeta_pinv,p,pinv);
    }

level6_8t15:
    for(j=0;j<2;j++) {
      zeta = _mm512_set1_epi16(prime->zetas->c[47-2*i-j]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[47-2*i-j]);
      gsbttrfly(&f[8*j],4,zeta,zeta_pinv,p,pinv);
    }

level5_8t15:
    zeta = _mm512_set1_epi16(prime->zetas->c[23-i]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[23-i]);
    gsbttrfly(&f[0],8,zeta,zeta_pinv,p,pinv);

    for(j=0;j<16;j++)
      _mm512_store_si512(&r[stride_r*(16*i+j)],f[j]);
  }

  if(len<=256) return;

  for(i=16;i<32;i++) {
    for(j=0;j<16;j++)
      f[j] = _mm512_load_si512(&r[stride_r*(16*i+j)]);

level8_16t31:
    zeta = _mm512_set1_epi16(prime->zetas->c[255-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[255-2*idx[i-16]]);
    gsbttrfly(&f[0],1,zeta,zeta_pinv,p,pinv);
    zeta = _mm512_set1_epi16(prime->zetas->c[223-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[223-2*idx[i-16]]);
    gsbttrfly(&f[2],1,zeta,zeta_pinv,p,pinv);
    zeta = _mm512_set1_epi16(prime->zetas->c[191-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[191-2*idx[i-16]]);
    gsbttrfly(&f[4],1,zeta,zeta_pinv,p,pinv);
    zeta = _mm512_set1_epi16(prime->zetas->c[159-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[159-2*idx[i-16]]);
    gsbttrfly(&f[6],1,zeta,zeta_pinv,p,pinv);
    zeta = _mm512_set1_epi16(prime->zetas->c[254-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[254-2*idx[i-16]]);
    gsbttrfly(&f[8],1,zeta,zeta_pinv,p,pinv);
    zeta = _mm512_set1_epi16(prime->zetas->c[222-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[222-2*idx[i-16]]);
    gsbttrfly(&f[10],1,zeta,zeta_pinv,p,pinv);
    zeta = _mm512_set1_epi16(prime->zetas->c[190-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[190-2*idx[i-16]]);
    gsbttrfly(&f[12],1,zeta,zeta_pinv,p,pinv);
    zeta = _mm512_set1_epi16(prime->zetas->c[158-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[158-2*idx[i-16]]);
    gsbttrfly(&f[14],1,zeta,zeta_pinv,p,pinv);

level7_16t31:
    zeta = _mm512_set1_epi16(prime->zetas->c[127-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[127-2*idx[i-16]]);
    gsbttrfly(&f[0],2,zeta,zeta_pinv,p,pinv);
    zeta = _mm512_set1_epi16(prime->zetas->c[95-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[95-2*idx[i-16]]);
    gsbttrfly(&f[4],2,zeta,zeta_pinv,p,pinv);
    zeta = _mm512_set1_epi16(prime->zetas->c[126-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[126-2*idx[i-16]]);
    gsbttrfly(&f[8],2,zeta,zeta_pinv,p,pinv);
    zeta = _mm512_set1_epi16(prime->zetas->c[94-2*idx[i-16]]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[94-2*idx[i-16]]);
    gsbttrfly(&f[12],2,zeta,zeta_pinv,p,pinv);

level6_16t31:
    for(j=0;j<2;j++) {
      zeta = _mm512_set1_epi16(prime->zetas->c[95-2*i-j]);
      zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[95-2*i-j]);
      gsbttrfly(&f[8*j],4,zeta,zeta_pinv,p,pinv);
    }

level5_16t31:
    zeta = _mm512_set1_epi16(prime->zetas->c[47-i]);
    zeta_pinv = _mm512_set1_epi16(prime->zetas_pinv->c[47-i]);
    gsbttrfly(&f[0],8,zeta,zeta_pinv,p,pinv);

    for(j=0;j<16;j++)
      _mm512_store_si512(&r[stride_r*(16*i+j)],f[j]);
  }
}

static inline void invntt_interleaved32_levels4t1(__m512i *r, ssize_t stride, size_t len, const pdata prime) {
  size_t i,j,k,l;
  __m512i f[16];
  __m512i zeta[8],zeta_pinv[8];
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

  zeta[0] = _mm512_set1_epi16(-prime->zetas->c[0]);
  zeta_pinv[0] = _mm512_set1_epi16(-prime->zetas_pinv->c[0]);
  zeta[1] = _mm512_set1_epi16(prime->zetas->c[1]);
  zeta_pinv[1] = _mm512_set1_epi16(prime->zetas_pinv->c[1]);
  zeta[2] = _mm512_set1_epi16(prime->zetas->c[3]);
  zeta_pinv[2] = _mm512_set1_epi16(prime->zetas_pinv->c[3]);
  zeta[3] = _mm512_set1_epi16(prime->zetas->c[2]);
  zeta_pinv[3] = _mm512_set1_epi16(prime->zetas_pinv->c[2]);
  for(i=4;i<8;i++) {
    zeta[i] = _mm512_set1_epi16(prime->zetas->c[11-i]);
    zeta_pinv[i] = _mm512_set1_epi16(prime->zetas_pinv->c[11-i]);
  }
  for(i=0;i<len/16;i++) {
    for(j=0;j<16;j++)
      f[j] = _mm512_load_si512(&r[stride*(len/16*j+i)]);
    for(l=256/len;l<16;l*=2) {
      k = 0;
      for(j=0;j<16;j+=2*l) {
        gsbttrfly(&f[j],l,zeta[k],zeta_pinv[k],p,pinv);
        k += 1;
      }
    }
    for(j=0;j<16;j++)
      _mm512_store_si512(&r[stride*(len/16*j+i)],f[j]);
  }
}

static inline void invntt_interleaved32_levels4t1_negacyclic(__m512i *r, ssize_t stride, size_t len, const pdata prime) {
  size_t i,j,k,l;
  __m512i f[16];
  __m512i zeta[len/16-1],zeta_pinv[len/16-1];
  const __m512i p = _mm512_set1_epi16(prime->p);
  const __m512i pinv = _mm512_set1_epi16(prime->pinv);

  for(i=0;i<len/16-1;i++) {
    zeta[i] = _mm512_set1_epi16(prime->zetas->c[len/16-1-i]);
    zeta_pinv[i] = _mm512_set1_epi16(prime->zetas_pinv->c[len/16-1-i]);
  }
  for(i=0;i<len/16;i++) {
    for(j=0;j<16;j++)
      f[j] = _mm512_load_si512(&r[stride*(len/16*j+i)]);
    k = 0;
    for(l=256/len;l<16;l*=2) {
      for(j=0;j<16;j+=2*l) {
        gsbttrfly(&f[j],l,zeta[k],zeta_pinv[k],p,pinv);
        k += 1;
      }
    }
    for(j=0;j<16;j++)
      _mm512_store_si512(&r[stride*(len/16*j+i)],f[j]);
  }
}

void polyvec_ntt_interleaved(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime) {
  size_t i;
  poly t;

  for(i=0;i<len/2;i++) {
    poly_add(t,a[stride_a*i],a[stride_a*(len/2+i)]);
    poly_sub(r[stride_r*(len/2+i)],a[stride_a*i],a[stride_a*(len/2+i)]);
    polyvec_copy(&r[stride_r*i],&t,0,0,1);
  }

  len /= 2;
  for(i=0;i<N/32;i++) {
    ntt_interleaved32_levels1t4(&r[0]->v[i],&r[0]->v[i],N/32*stride_r,N/32*stride_r,len,prime);
    ntt_interleaved32_levels5t8(&r[0]->v[i],N/32*stride_r,len,prime);
    ntt_interleaved32_levels1t4_negacyclic(&r[len*stride_r]->v[i],&r[len*stride_r]->v[i],
                                           N/32*stride_r,N/32*stride_r,len,prime);
    ntt_interleaved32_levels5t8_negacyclic(&r[len*stride_r]->v[i],N/32*stride_r,len,prime);
  }
}

void polyvec_ntt_interleaved_half(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime) {
  size_t i;

  len /= 2;
  for(i=0;i<N/32;i++) {
    ntt_interleaved32_levels1t4(&r[0]->v[i],&a[0]->v[i],N/32*stride_r,N/32*stride_a,len,prime);
    ntt_interleaved32_levels5t8(&r[0]->v[i],N/32*stride_r,len,prime);
    ntt_interleaved32_levels1t4_negacyclic(&r[len*stride_r]->v[i],&a[0]->v[i],
                                           N/32*stride_r,N/32*stride_a,len,prime);
    ntt_interleaved32_levels5t8_negacyclic(&r[len*stride_r]->v[i],N/32*stride_r,len,prime);
  }
}

void polyvec_invntt_interleaved(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime) {
  size_t i;
  int16_t s;
  poly t[2];

  for(i=0;i<N/32;i++) {
    invntt_interleaved32_levels8t5(&r[0]->v[i],&a[0]->v[i],N/32*stride_r,N/32*stride_a,len,prime);
    invntt_interleaved32_levels4t1(&r[0]->v[i],N/32*stride_r,len/2,prime);
    invntt_interleaved32_levels4t1_negacyclic(&r[len/2*stride_r]->v[i],N/32*stride_r,len/2,prime);
  }

  s = pow_simple(len,15,prime);
  for(i=0;i<len/2;i++) {
    poly_add(t[0],r[stride_r*i],r[stride_r*(len/2+i)]);
    poly_sub(t[1],r[stride_r*i],r[stride_r*(len/2+i)]);
    polyvec_scale(&r[stride_r*i],t,stride_r*len/2,1,2,s,prime);
  }
}

