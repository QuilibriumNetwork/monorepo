#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <string.h>
#include "data.h"
#include "polz.h"
#include "jlproj.h"

/* Substracting 2 iid random variables with P(-1)=0.5, P(1)=0.5
 * gives random variable with P(-2)=0.25, P(0)=0.5, P(2)=0.25.
 * Divide by 2 to obtain the correct distribution:
 * P(-1)=0.25, P(0)=0.5, P(1)=0.25
 *
 * m1 = mat1
 * m2 = mat2 // interpreted as negative
 * r += ((m1 - (-m2)) / 2) * p
 */
void polyvec_jlproj_add_bin1(
  int32_t r[256], 
  const poly *p, 
  size_t len, 
  const uint8_t *mat1,
  const uint8_t *mat2
) 
{
  size_t i;
  polyvec_jlproj_add(r, p, len, mat1);
  polyvec_jlproj_add(r, p, len, mat2);
  for (i = 0; i < 256; i++)
    r[i] >>= 1;
}

/* matrix format (32x16):
 * 4 bits -> nibble: 8 row stride
 * 2 nibbles -> byte: 8 col stride
 * 4 bytes -> dword: 1 row stride
 * 2 dwords -> qword: 4 row stride
 * 8 qwords -> zvec: 1 col stride
 */

static void jlproj_add64(int32_t out[256], const int16_t in[64], const uint8_t mat[256*64/8]) {
  int i;
  __m512i a,b,c,d;
  __m512i e,f,g,h;
  __m512i k,l,m,n;
  __m512i o,p,q,r;
  __m512i s,t,u,v;
  __m512i w,x,y,z;
  const __m512i zero = _mm512_setzero_si512();
  const __m512i stencil1 = _mm512_set1_epi8(0x11);
  const __m512i stencil2 = _mm512_set1_epi8(0x22);
  const __m512i stencil4 = _mm512_set1_epi8(0x44);
  const __m512i stencil8 = _mm512_set1_epi8((char)0x88);
  const __m512i vpermi2bidx = _mm512_set_epi8(95,87,79,71,
                                              94,86,78,70,
                                              93,85,77,69,
                                              92,84,76,68,
                                              91,83,75,67,
                                              90,82,74,66,
                                              89,81,73,65,
                                              88,80,72,64,
                                              31,23,15, 7,
                                              30,22,14, 6,
                                              29,21,13, 5,
                                              28,20,12, 4,
                                              27,19,11, 3,
                                              26,18,10, 2,
                                              25,17, 9, 1,
                                              24,16, 8, 0);

  /* Prepare 16 vectors containing all 16 signed combinations of 4 polynomial coeffs that are 16 apart */
  a = _mm512_cvtepi16_epi32(_mm256_load_si256((__m256i*)&in[48]));
  b = _mm512_cvtepi16_epi32(_mm256_load_si256((__m256i*)&in[32]));

  e = _mm512_add_epi32(a,b);     // ++
  f = _mm512_sub_epi32(a,b);     // +-
  g = _mm512_sub_epi32(b,a);     // -+
  h = _mm512_sub_epi32(zero,e);  // --

  a = _mm512_shuffle_i64x2(e,f,0x44);  // ++,+-
  b = _mm512_shuffle_i64x2(e,f,0xEE);  // ++,+-
  c = _mm512_shuffle_i64x2(g,h,0x44);  // -+,--
  d = _mm512_shuffle_i64x2(g,h,0xEE);  // -+,--

  e = _mm512_shuffle_i64x2(a,c,0x88);  // ++,+-,-+,--
  f = _mm512_shuffle_i64x2(a,c,0xDD);  // ++,+-,-+,--
  g = _mm512_shuffle_i64x2(b,d,0x88);  // ++,+-,-+,--
  h = _mm512_shuffle_i64x2(b,d,0xDD);  // ++,+-,-+,--

  a = _mm512_cvtepi16_epi32(_mm256_load_si256((__m256i*)&in[16]));
  b = _mm512_cvtepi16_epi32(_mm256_load_si256((__m256i*)&in[ 0]));

  c = _mm512_add_epi32(a,b);  // ++
  d = _mm512_sub_epi32(a,b);  // +-

  k = _mm512_shuffle_i64x2(c,c,0x00);  // ++,++,++,++
  l = _mm512_shuffle_i64x2(c,c,0x55);  // ++,++,++,++
  m = _mm512_shuffle_i64x2(c,c,0xAA);  // ++,++,++,++
  n = _mm512_shuffle_i64x2(c,c,0xFF);  // ++,++,++,++
  o = _mm512_shuffle_i64x2(d,d,0x00);  // +-,+-,+-,+-
  p = _mm512_shuffle_i64x2(d,d,0x55);  // +-,+-,+-,+-
  q = _mm512_shuffle_i64x2(d,d,0xAA);  // +-,+-,+-,+-
  r = _mm512_shuffle_i64x2(d,d,0xFF);  // +-,+-,+-,+-

  s = _mm512_add_epi32(e,k);  // ++++,+-++,-+++,--++
  t = _mm512_add_epi32(e,o);  // +++-,+-+-,-++-,--+-
  u = _mm512_sub_epi32(e,o);  // ++-+,+--+,-+-+,---+
  v = _mm512_sub_epi32(e,k);  // ++--,+---,-+--,----
  w = _mm512_add_epi32(f,l);  // ++++,+-++,-+++,--++
  x = _mm512_add_epi32(f,p);  // +++-,+-+-,-++-,--+-
  y = _mm512_sub_epi32(f,p);  // ++-+,+--+,-+-+,---+
  z = _mm512_sub_epi32(f,l);  // ++--,+---,-+--,----
  a = _mm512_add_epi32(g,m);  // ++++,+-++,-+++,--++
  b = _mm512_add_epi32(g,q);  // +++-,+-+-,-++-,--+-
  c = _mm512_sub_epi32(g,q);  // ++-+,+--+,-+-+,---+
  d = _mm512_sub_epi32(g,m);  // ++--,+---,-+--,----
  e = _mm512_add_epi32(h,n);  // ++++,+-++,-+++,--++
  f = _mm512_add_epi32(h,r);  // +++-,+-+-,-++-,--+-
  g = _mm512_sub_epi32(h,r);  // ++-+,+--+,-+-+,---+
  h = _mm512_sub_epi32(h,n);  // ++--,+---,-+--,----

  k = _mm512_unpacklo_epi32(s,t);  // ++++,+++-,+-++,+-+-,-+++,-++-,--++,--+-
  l = _mm512_unpacklo_epi32(u,v);  // ++-+,++--,+--+,+---,-+-+,-+--,---+,----
  m = _mm512_unpackhi_epi32(s,t);  // ++++,+++-,+-++,+-+-,-+++,-++-,--++,--+-
  n = _mm512_unpackhi_epi32(u,v);  // ++-+,++--,+--+,+---,-+-+,-+--,---+,----
  o = _mm512_unpacklo_epi32(w,x);  // ++++,+++-,+-++,+-+-,-+++,-++-,--++,--+-
  p = _mm512_unpacklo_epi32(y,z);  // ++-+,++--,+--+,+---,-+-+,-+--,---+,----
  q = _mm512_unpackhi_epi32(w,x);  // ++++,+++-,+-++,+-+-,-+++,-++-,--++,--+-
  r = _mm512_unpackhi_epi32(y,z);  // ++-+,++--,+--+,+---,-+-+,-+--,---+,----
  s = _mm512_unpacklo_epi32(a,b);  // ++++,+++-,+-++,+-+-,-+++,-++-,--++,--+-
  t = _mm512_unpacklo_epi32(c,d);  // ++-+,++--,+--+,+---,-+-+,-+--,---+,----
  u = _mm512_unpackhi_epi32(a,b);  // ++++,+++-,+-++,+-+-,-+++,-++-,--++,--+-
  v = _mm512_unpackhi_epi32(c,d);  // ++-+,++--,+--+,+---,-+-+,-+--,---+,----
  w = _mm512_unpacklo_epi32(e,f);  // ++++,+++-,+-++,+-+-,-+++,-++-,--++,--+-
  x = _mm512_unpacklo_epi32(g,h);  // ++-+,++--,+--+,+---,-+-+,-+--,---+,----
  y = _mm512_unpackhi_epi32(e,f);  // ++++,+++-,+-++,+-+-,-+++,-++-,--++,--+-
  z = _mm512_unpackhi_epi32(g,h);  // ++-+,++--,+--+,+---,-+-+,-+--,---+,----

  a = _mm512_unpacklo_epi64(k,l);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  b = _mm512_unpackhi_epi64(k,l);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  c = _mm512_unpacklo_epi64(m,n);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  d = _mm512_unpackhi_epi64(m,n);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  e = _mm512_unpacklo_epi64(o,p);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  f = _mm512_unpackhi_epi64(o,p);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  g = _mm512_unpacklo_epi64(q,r);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  h = _mm512_unpackhi_epi64(q,r);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  k = _mm512_unpacklo_epi64(s,t);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  l = _mm512_unpackhi_epi64(s,t);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  m = _mm512_unpacklo_epi64(u,v);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  n = _mm512_unpackhi_epi64(u,v);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  o = _mm512_unpacklo_epi64(w,x);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  p = _mm512_unpackhi_epi64(w,x);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  q = _mm512_unpacklo_epi64(y,z);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----
  r = _mm512_unpackhi_epi64(y,z);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---,-+++,-++-,-+-+,-+--,--++,--+-,---+,----

  for(i=0;i<256/32;i++) {
    s = _mm512_load_si512((__m512i*)&mat[32*16/8*i+256*16/8*0]);
    t = _mm512_load_si512((__m512i*)&mat[32*16/8*i+256*16/8*1]);
    u = _mm512_load_si512((__m512i*)&mat[32*16/8*i+256*16/8*2]);
    v = _mm512_load_si512((__m512i*)&mat[32*16/8*i+256*16/8*3]);

    x = _mm512_slli_epi32(t,1);
    y = _mm512_slli_epi32(u,2);
    z = _mm512_slli_epi32(v,3);
    w = _mm512_and_si512(s,stencil1);
    x = _mm512_and_si512(x,stencil2);
    y = _mm512_and_si512(y,stencil4);
    z = _mm512_and_si512(z,stencil8);
    w = _mm512_add_epi8(w,x);
    x = _mm512_add_epi8(y,z);
    w = _mm512_add_epi8(w,x);

    x = _mm512_srli_epi32(s,1);
    x = _mm512_and_si512(x,stencil1);
    y = _mm512_and_si512(t,stencil2);
    x = _mm512_add_epi8(x,y);
    y = _mm512_slli_epi32(u,1);
    z = _mm512_slli_epi32(v,2);
    y = _mm512_and_si512(y,stencil4);
    z = _mm512_and_si512(z,stencil8);
    y = _mm512_add_epi8(y,z);
    x = _mm512_add_epi8(x,y);

    y = _mm512_permutex2var_epi8(w,vpermi2bidx,x);
    z = _mm512_add_epi8(vpermi2bidx,_mm512_set1_epi8(32));
    z = _mm512_permutex2var_epi8(w,z,x);

#define BLOCK(T0,T1)                  \
  x = _mm512_permutexvar_epi32(y,T0); \
  w = _mm512_add_epi32(w,x);          \
  x = _mm512_permutexvar_epi32(z,T1); \
  y = _mm512_srli_epi32(y,4);         \
  z = _mm512_srli_epi32(z,4);         \
  w = _mm512_add_epi32(w,x)

    w = _mm512_loadu_si512((__m512i*)&out[32*i+ 0]);
    BLOCK(a,e);
    BLOCK(k,o);
    BLOCK(b,f);
    BLOCK(l,p);
    BLOCK(c,g);
    BLOCK(m,q);
    BLOCK(d,h);
    BLOCK(n,r);
    _mm512_storeu_si512((__m512i*)&out[32*i+ 0],w);

    w = _mm512_srli_epi32(s,2);
    x = _mm512_srli_epi32(t,1);
    z = _mm512_slli_epi32(v,1);
    w = _mm512_and_si512(w,stencil1);
    x = _mm512_and_si512(x,stencil2);
    y = _mm512_and_si512(u,stencil4);
    z = _mm512_and_si512(z,stencil8);
    w = _mm512_add_epi8(w,x);
    x = _mm512_add_epi8(y,z);
    w = _mm512_add_epi8(w,x);

    x = _mm512_srli_epi32(s,3);
    y = _mm512_srli_epi32(t,2);
    x = _mm512_and_si512(x,stencil1);
    y = _mm512_and_si512(y,stencil2);
    x = _mm512_add_epi8(x,y);
    y = _mm512_srli_epi32(u,1);
    y = _mm512_and_si512(y,stencil4);
    z = _mm512_and_si512(v,stencil8);
    y = _mm512_add_epi8(y,z);
    x = _mm512_add_epi8(x,y);

    y = _mm512_permutex2var_epi8(w,vpermi2bidx,x);
    z = _mm512_add_epi8(vpermi2bidx,_mm512_set1_epi8(32));
    z = _mm512_permutex2var_epi8(w,z,x);

    w = _mm512_loadu_si512((__m512i*)&out[32*i+16]);
    BLOCK(a,e);
    BLOCK(k,o);
    BLOCK(b,f);
    BLOCK(l,p);
    BLOCK(c,g);
    BLOCK(m,q);
    BLOCK(d,h);
    BLOCK(n,r);
    _mm512_storeu_si512((__m512i*)&out[32*i+16],w);

#undef BLOCK
  }
}

void poly_jlproj_add(int32_t out[256], const poly in, const uint8_t mat[256*N/8]) {
  size_t i;

  for(i=0;i<N/64;i++)
    jlproj_add64(out,&in->c[64*i],&mat[2048*i]);
}

void polyvec_jlproj_add(int32_t r[256], const poly *p, size_t len, const uint8_t *mat) {
  size_t i;

  for(i=0;i<len;i++)
    poly_jlproj_add(r,p[i],&mat[256*N/8*i]);
}

static void jlproj_collapsmat32(int64_t *row, const uint8_t *mat, size_t len, const int64_t alpha[32]) {
  size_t i;
  __m512i a,b,c,d;
  __m512i e,f,g,h;
  __m512i k,l,m,n;
  __m512i o,p,q,r;
  __m512i s,t,u,v;
  __m512i w,x,y,z;
  const __m512i zero = _mm512_setzero_si512();

  /* Prepare 8 pairs of vectors containing all 16 signed combinations of 4 challenge coeffs that are 8 apart */
  a = _mm512_load_si512((__m512i*)&alpha[24]);
  b = _mm512_load_si512((__m512i*)&alpha[16]);

  e = _mm512_add_epi64(a,b);     // ++
  f = _mm512_sub_epi64(a,b);     // +-
  g = _mm512_sub_epi64(b,a);     // -+
  h = _mm512_sub_epi64(zero,e);  // --

  s = _mm512_shuffle_i64x2(e,f,0x00);  // ++,++,+-,+-
  t = _mm512_shuffle_i64x2(e,f,0x55);  // ++,++,+-,+-
  u = _mm512_shuffle_i64x2(e,f,0xAA);  // ++,++,+-,+-
  v = _mm512_shuffle_i64x2(e,f,0xFF);  // ++,++,+-,+-
  w = _mm512_shuffle_i64x2(g,h,0x00);  // -+,-+,--,--
  x = _mm512_shuffle_i64x2(g,h,0x55);  // -+,-+,--,--
  y = _mm512_shuffle_i64x2(g,h,0xAA);  // -+,-+,--,--
  z = _mm512_shuffle_i64x2(g,h,0xFF);  // -+,-+,--,--

  a = _mm512_load_si512((__m512i*)&alpha[ 8]);
  b = _mm512_load_si512((__m512i*)&alpha[ 0]);

  c = _mm512_add_epi64(a,b);  // ++
  d = _mm512_sub_epi64(b,a);  // -+

  k = _mm512_shuffle_i64x2(c,d,0x44);  // ++,-+
  l = _mm512_shuffle_i64x2(c,d,0xEE);  // ++,-+
  a = _mm512_shuffle_i64x2(k,k,0x88);  // ++,-+,++,-+
  b = _mm512_shuffle_i64x2(k,k,0xDD);  // ++,-+,++,-+
  c = _mm512_shuffle_i64x2(l,l,0x88);  // ++,-+,++,-+
  d = _mm512_shuffle_i64x2(l,l,0xDD);  // ++,-+,++,-+
  e = _mm512_shuffle_i64x2(k,k,0x22);  // -+,++,-+,++
  f = _mm512_shuffle_i64x2(k,k,0x77);  // -+,++,-+,++
  g = _mm512_shuffle_i64x2(l,l,0x22);  // -+,++,-+,++
  h = _mm512_shuffle_i64x2(l,l,0x77);  // -+,++,-+,++

  k = _mm512_add_epi64(s,a);  // ++++,++-+,+-++,+--+
  l = _mm512_add_epi64(t,b);  // ++++,++-+,+-++,+--+
  m = _mm512_add_epi64(u,c);  // ++++,++-+,+-++,+--+
  n = _mm512_add_epi64(v,d);  // ++++,++-+,+-++,+--+
  o = _mm512_sub_epi64(s,e);  // +++-,++--,+-+-,+---
  p = _mm512_sub_epi64(t,f);  // +++-,++--,+-+-,+---
  q = _mm512_sub_epi64(u,g);  // +++-,++--,+-+-,+---
  r = _mm512_sub_epi64(v,h);  // +++-,++--,+-+-,+---
  s = _mm512_add_epi64(w,a);  // -+++,-+-+,--++,+--+
  t = _mm512_add_epi64(x,b);  // -+++,-+-+,--++,+--+
  u = _mm512_add_epi64(y,c);  // -+++,-+-+,--++,+--+
  v = _mm512_add_epi64(z,d);  // -+++,-+-+,--++,+--+
  w = _mm512_sub_epi64(w,e);  // -++-,-+--,--+-,----
  x = _mm512_sub_epi64(x,f);  // -++-,-+--,--+-,----
  y = _mm512_sub_epi64(y,g);  // -++-,-+--,--+-,----
  z = _mm512_sub_epi64(z,h);  // -++-,-+--,--+-,----

  a = _mm512_unpacklo_epi64(k,o);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  b = _mm512_unpackhi_epi64(k,o);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  c = _mm512_unpacklo_epi64(l,p);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  d = _mm512_unpackhi_epi64(l,p);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  e = _mm512_unpacklo_epi64(m,q);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  f = _mm512_unpackhi_epi64(m,q);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  g = _mm512_unpacklo_epi64(n,r);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  h = _mm512_unpackhi_epi64(n,r);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  k = _mm512_unpacklo_epi64(s,w);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  l = _mm512_unpackhi_epi64(s,w);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  m = _mm512_unpacklo_epi64(t,x);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  n = _mm512_unpackhi_epi64(t,x);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  o = _mm512_unpacklo_epi64(u,y);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  p = _mm512_unpackhi_epi64(u,y);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  q = _mm512_unpacklo_epi64(v,z);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  r = _mm512_unpackhi_epi64(v,z);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----

#if 0
  const __m125i revidx = _mm512_set_epi64(0,1,2,3,4,5,6,7);

  a = _mm512_loadu_si256((__m512i*)&alpha[ 0]));
  b = _mm512_loadu_si256((__m512i*)&alpha[ 8]));
  c = _mm512_loadu_si256((__m512i*)&alpha[16]));
  d = _mm512_loadu_si256((__m512i*)&alpha[24]));

  e = _mm512_add_epi64(a,b);  // ++ (a+b)
  f = _mm512_sub_epi64(a,b);  // +- (a-b)
  g = _mm512_add_epi64(c,d);  // ++ (c+d)
  h = _mm512_sub_epi64(c,d);  // +- (c-d)

  k = _mm512_add_epi64(e,g);  // ++++
  l = _mm512_add_epi64(e,h);  // +++-
  m = _mm512_sub_epi64(e,h);  // ++-+
  n = _mm512_sub_epi64(e,g);  // ++--
  o = _mm512_add_epi64(f,g);  // +-++
  p = _mm512_add_epi64(f,h);  // +-+-
  q = _mm512_sub_epi64(f,h);  // +--+
  r = _mm512_sub_epi64(f,g);  // +---

  a = _mm512_shuffle_i64x2(k,m,0x44);  // ++++,++-+
  b = _mm512_shuffle_i64x2(k,m,0xEE);  // ++++,++-+
  c = _mm512_shuffle_i64x2(l,n,0x44);  // +++-,++--
  d = _mm512_shuffle_i64x2(l,n,0xEE);  // +++-,++--
  e = _mm512_shuffle_i64x2(o,q,0x44);  // +-++,+--+
  f = _mm512_shuffle_i64x2(o,q,0xEE);  // +-++,+--+
  g = _mm512_shuffle_i64x2(p,r,0x44);  // +-+-,+---
  h = _mm512_shuffle_i64x2(p,r,0xEE);  // +-+-,+---

  k = _mm512_shuffle_i64x2(a,e,0x88);  // ++++,++-+,+-++,+--+
  l = _mm512_shuffle_i64x2(a,e,0xDD);  // ++++,++-+,+-++,+--+
  m = _mm512_shuffle_i64x2(b,f,0x88);  // ++++,++-+,+-++,+--+
  n = _mm512_shuffle_i64x2(b,f,0xDD);  // ++++,++-+,+-++,+--+
  o = _mm512_shuffle_i64x2(c,g,0x88);  // +++-,++--,+-+-,+---
  p = _mm512_shuffle_i64x2(c,g,0xDD);  // +++-,++--,+-+-,+---
  q = _mm512_shuffle_i64x2(d,h,0x88);  // +++-,++--,+-+-,+---
  r = _mm512_shuffle_i64x2(d,h,0xDD);  // +++-,++--,+-+-,+---

  a = _mm512_unpacklo_epi64(k,o);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  b = _mm512_unpackhi_epi64(k,o);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  c = _mm512_unpacklo_epi64(l,p);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  d = _mm512_unpackhi_epi64(l,p);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  e = _mm512_unpacklo_epi64(m,q);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  f = _mm512_unpackhi_epi64(m,q);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  g = _mm512_unpacklo_epi64(n,r);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---
  h = _mm512_unpackhi_epi64(n,r);  // ++++,+++-,++-+,++--,+-++,+-+-,+--+,+---

  k = _mm512_sub_epi64(zero,a);  // ----,---+,--+-,--++,-+--,-+-+,-++-,-+++
  l = _mm512_sub_epi64(zero,b);  // ----,---+,--+-,--++,-+--,-+-+,-++-,-+++
  m = _mm512_sub_epi64(zero,c);  // ----,---+,--+-,--++,-+--,-+-+,-++-,-+++
  n = _mm512_sub_epi64(zero,d);  // ----,---+,--+-,--++,-+--,-+-+,-++-,-+++
  o = _mm512_sub_epi64(zero,e);  // ----,---+,--+-,--++,-+--,-+-+,-++-,-+++
  p = _mm512_sub_epi64(zero,f);  // ----,---+,--+-,--++,-+--,-+-+,-++-,-+++
  q = _mm512_sub_epi64(zero,g);  // ----,---+,--+-,--++,-+--,-+-+,-++-,-+++
  r = _mm512_sub_epi64(zero,h);  // ----,---+,--+-,--++,-+--,-+-+,-++-,-+++

  k = _mm512_permutexvar_epi64(revidx,k);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  l = _mm512_permutexvar_epi64(revidx,l);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  m = _mm512_permutexvar_epi64(revidx,m);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  n = _mm512_permutexvar_epi64(revidx,n);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  o = _mm512_permutexvar_epi64(revidx,o);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  p = _mm512_permutexvar_epi64(revidx,p);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  q = _mm512_permutexvar_epi64(revidx,q);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
  r = _mm512_permutexvar_epi64(revidx,r);  // -+++,-++-,-+-+,-+--,--++,--+-,---+,----
#endif

#define BLOCK(T0,T1)                      \
  u = _mm512_permutex2var_epi64(T0,s,T1); \
  v = _mm512_permutex2var_epi64(T0,t,T1); \
  s = _mm512_srli_epi64(s,4);             \
  t = _mm512_srli_epi64(t,4);             \
  w = _mm512_add_epi64(w,u);              \
  y = _mm512_add_epi64(y,v);              \
  u = _mm512_permutex2var_epi64(T0,s,T1); \
  v = _mm512_permutex2var_epi64(T0,t,T1); \
  s = _mm512_srli_epi64(s,4);             \
  t = _mm512_srli_epi64(t,4);             \
  x = _mm512_add_epi64(x,u);              \
  z = _mm512_add_epi64(z,v)

  for(i=0;i<len/32;i++) {
    s = _mm512_load_si512((__m512i*)&mat[256*32/8*i+       0]);
    t = _mm512_load_si512((__m512i*)&mat[256*32/8*i+256*16/8]);
    w = _mm512_load_si512((__m512i*)&row[32*i+ 0]);
    x = _mm512_load_si512((__m512i*)&row[32*i+ 8]);
    y = _mm512_load_si512((__m512i*)&row[32*i+16]);
    z = _mm512_load_si512((__m512i*)&row[32*i+24]);
    BLOCK(a,k);
    BLOCK(b,l);
    BLOCK(c,m);
    BLOCK(d,n);
    BLOCK(e,o);
    BLOCK(f,p);
    BLOCK(g,q);
    BLOCK(h,r);
    _mm512_store_si512((__m512i*)&row[32*i+ 0],w);
    _mm512_store_si512((__m512i*)&row[32*i+ 8],x);
    _mm512_store_si512((__m512i*)&row[32*i+16],y);
    _mm512_store_si512((__m512i*)&row[32*i+24],z);
  }

#undef BLOCK
}

void jlproj_expand_challenge(int64_t alpha[256], const uint8_t buf[256*QBYTES]) {
  int i;
  __m512i f;

#if QBYTES == 3
  const __mmask64 mask = _cvtu64_mask64(0x0B0B0B0B0B0B0B0Bull);
  const __m512i vpermbidx = _mm512_set_epi8(-1,-1,-1,-1,-1,23,22,21,
                                            -1,-1,-1,-1,-1,20,19,18,
                                            -1,-1,-1,-1,-1,17,16,15,
                                            -1,-1,-1,-1,-1,14,13,12,
                                            -1,-1,-1,-1,-1,11,10, 9,
                                            -1,-1,-1,-1,-1, 8, 7, 6,
                                            -1,-1,-1,-1,-1, 5, 4, 3,
                                            -1,-1,-1,-1,-1, 2, 1, 0);
  for(i=0;i<256/8;i++) {
    f = _mm512_loadu_si512((__m512i*)&buf[24*i]);
    f = _mm512_maskz_permutexvar_epi8(mask,vpermbidx,f);
    _mm512_store_si512((__m512i*)&alpha[8*i],f);
  }
#elif QBYTES == 4
  for(i=0;i<256/8;i++) {
    f = _mm512_cvtepu32_epi64(_mm256_load_si256((__m256i*)&buf[32*i]));
    _mm512_store_si512((__m512i*)&alpha[8*i],f);
  }
#elif QBYTES == 5
  const __mmask64 mask = _cvtu64_mask64(0x1F1F1F1F1F1F1F1Full);
  const __m512i vpermbidx = _mm512_set_epi8(-1,-1,-1,39,38,37,36,35,
                                            -1,-1,-1,34,33,32,31,30,
                                            -1,-1,-1,29,28,27,26,25,
                                            -1,-1,-1,24,23,22,21,20,
                                            -1,-1,-1,19,18,17,16,15,
                                            -1,-1,-1,14,13,12,11,10,
                                            -1,-1,-1, 9, 8, 7, 6, 5,
                                            -1,-1,-1, 4, 3, 2, 1, 0);
  for(i=0;i<256/8;i++) {
    f = _mm512_loadu_si512((__m512i*)&buf[40*i]);
    f = _mm512_maskz_permutexvar_epi8(mask,vpermbidx,f);
    _mm512_store_si512((__m512i*)&alpha[8*i],f);
  }
#elif QBYTES == 6
  const __mmask64 mask = _cvtu64_mask64(0x3F3F3F3F3F3F3F3Full);
  const __m512i vpermbidx = _mm512_set_epi8(-1,-1,47,46,45,44,43,42,
                                            -1,-1,41,40,39,38,37,36,
                                            -1,-1,35,34,33,32,31,30,
                                            -1,-1,29,28,27,26,25,24,
                                            -1,-1,23,22,21,20,19,18,
                                            -1,-1,17,16,15,14,13,12,
                                            -1,-1,11,10, 9, 8, 7, 6,
                                            -1,-1, 5, 4, 3, 2, 1, 0);
  for(i=0;i<256/8;i++) {
    f = _mm512_loadu_si512((__m512i*)&buf[48*i]);
    f = _mm512_maskz_permutexvar_epi8(mask,vpermbidx,f);
    _mm512_store_si512((__m512i*)&alpha[8*i],f);
  }
#else
#error
#endif
}

void polxvec_jlproj_collapsmat(polxvec r, const uint8_t *mat, const int64_t alpha[256]) {
  size_t i,j,k;
  __m512i f,g;
  const __m512i qoff = _mm512_set1_epi64(QOFF);
  const __m512i mask = _mm512_set1_epi64(((uint64_t)1 << LOGQ) - 1);
  const __m512i mask14 = _mm512_set1_epi64((1 << 14) - 1);
  const __mmask32 oneinfour = _cvtu32_mask32(0x11111111);
  _Alignas(64) int64_t raw[16*N];
  polz t[16];
  size_t rpos = 0;
  size_t len = r->len;

  while(len >= 16) {
    for(i=0;i<16*N;i++)
      raw[i] = 0;
    for(i=0;i<256/32;i++)
      jlproj_collapsmat32(raw,&mat[32*16/8*i],16*N,&alpha[32*i]);

    for(i=0;i<16;i++) {
      for(j=0;j<N/8;j++) {
        f = _mm512_load_si512((__m512i*)&raw[N*i+8*j]);
        g = _mm512_srai_epi64(f,LOGQ);
        f = _mm512_and_si512(f,mask);
        g = _mm512_mul_epi32(g,qoff);
        f = _mm512_add_epi64(f,g);
        for(k=0;k<L-1;k++) {
          g = _mm512_and_si512(f,mask14);
          f = _mm512_srai_epi64(f,14);
          _mm512_mask_compressstoreu_epi16(&t[i]->limbs[k]->c[8*j],oneinfour,g);
        }
        _mm512_mask_compressstoreu_epi16(&t[i]->limbs[L-1]->c[8*j],oneinfour,f);
      }
    }
    polzvec_sigmam1(t,t,16);
    polzvec_topolxvec(r,t,rpos,1,16);
    rpos += 16;
    mat += 256*16*N/8;
    len -= 16;
  }

  if(len) {
    for(i=0;i<len*N;i++)
      raw[i] = 0;
    for(i=0;i<256/32;i++)
      jlproj_collapsmat32(raw,&mat[32*16/8*i],len*N,&alpha[32*i]);

    for(i=0;i<len;i++) {
      for(j=0;j<N/8;j++) {
        f = _mm512_load_si512((__m512i*)&raw[N*i+8*j]);
        g = _mm512_srai_epi64(f,LOGQ);
        f = _mm512_and_si512(f,mask);
        g = _mm512_mul_epi32(g,qoff);
        f = _mm512_add_epi64(f,g);
        for(k=0;k<L-1;k++) {
          g = _mm512_and_si512(f,mask14);
          f = _mm512_srai_epi64(f,14);
          _mm512_mask_compressstoreu_epi16(&t[i]->limbs[k]->c[8*j],oneinfour,g);
        }
        _mm512_mask_compressstoreu_epi16(&t[i]->limbs[L-1]->c[8*j],oneinfour,f);
      }
    }
    polzvec_sigmam1(t,t,len);
    polzvec_topolxvec(r,t,rpos,1,len);
  }
}

static inline int64_t _mm512_hsum_epi64(__m512i a) {
  __m256i t;
  __m128i u;
  t = _mm256_add_epi64(_mm512_castsi512_si256(a),_mm512_extracti64x4_epi64(a,1));
  u = _mm_add_epi64(_mm256_castsi256_si128(t),_mm256_extracti64x2_epi64(t,1));
  u = _mm_add_epi64(u,_mm_unpackhi_epi64(u,u));
  return _mm_cvtsi128_si64(u);
}

int64_t jlproj_collapsproj(const int32_t p[256], const int64_t alpha[256]) {
  int i;
  int64_t r,t;
  __m512i f,g,h,s;
  const __m512i mask = _mm512_set1_epi64(((uint64_t)1 << LOGQ) - 1);
  const __m512i qoff = _mm512_set1_epi64(QOFF);

  s = _mm512_setzero_si512();
  for(i=0;i<256/8;i++) {
    f = _mm512_cvtepi32_epi64(_mm256_loadu_si256((__m256i*)&p[8*i]));
    g = _mm512_load_si512((__m512i*)&alpha[8*i]);
    h = _mm512_mul_epi32(f,g);
    s = _mm512_add_epi64(s,h);
#if LOGQ >= 32
    h = _mm512_srli_epi32(g,31);
    g = _mm512_srli_epi64(g,32);
    g = _mm512_add_epi64(g,h);
    f = _mm512_mul_epi32(f,g);
    g = _mm512_srai_epi64(f,LOGQ-32);  // 2^31
    f = _mm512_slli_epi64(f,32);
    f = _mm512_and_si512(f,mask);
    s = _mm512_add_epi64(s,f);
    g = _mm512_mul_epi32(g,qoff);
    s = _mm512_add_epi64(s,g);
#endif
    f = _mm512_srai_epi64(s,LOGQ);
    s = _mm512_and_si512(s,mask);
    f = _mm512_mul_epi32(f,qoff);
    s = _mm512_add_epi64(s,f);
  }

  r = _mm512_hsum_epi64(s);
  t = r >> LOGQ;
  r &= ((int64_t)1 << LOGQ) - 1;
  r += t*QOFF;
  return r;
}

uint64_t jlproj_normsq(const int32_t p[256]) {
  int i;
  __m512i f,g,s;

  s = _mm512_setzero_si512();
  for(i=0;i<256/16;i++) {
    f = _mm512_loadu_si512(&p[16*i]);
    g = _mm512_mul_epi32(f,f);
    f = _mm512_srli_epi64(f,32);
    f = _mm512_mul_epi32(f,f);
    f = _mm512_add_epi64(f,g);
    s = _mm512_add_epi64(f,s);
  }

  return _mm512_hsum_epi64(s);
}
