/* ARM64 portability probe adapters. */
#pragma once
#define SIMDE_ENABLE_NATIVE_ALIASES
#include <simde/x86/avx512.h>
#include <simde/x86/aes.h>
#include <simde/x86/gfni.h>
#include <stdint.h>
#include <string.h>
#if defined(__aarch64__) && !defined(SIMDE_NO_NATIVE)
#include <arm_neon.h>
/* Exact signed high half of each 16x16 product, with no saturation. */
static inline __m512i quil_arm_mulhi_epi16(__m512i a, __m512i b) {
  simde__m512i_private aa=simde__m512i_to_private(a);
  simde__m512i_private bb=simde__m512i_to_private(b), rr;
  for(size_t i=0;i<4;i++) {
    int16x8_t x=aa.m128i_private[i].neon_i16;
    int16x8_t y=bb.m128i_private[i].neon_i16;
    int32x4_t low=vmull_s16(vget_low_s16(x),vget_low_s16(y));
    int32x4_t high=vmull_high_s16(x,y);
    rr.m128i_private[i].neon_i16=vcombine_s16(vshrn_n_s32(low,16),vshrn_n_s32(high,16));
  }
  return simde__m512i_from_private(rr);
}
#undef _mm512_mulhi_epi16
#define _mm512_mulhi_epi16(a,b) quil_arm_mulhi_epi16(a,b)
#endif
#define _cvtu32_mask32(x) ((__mmask32)(x))
#define _cvtu64_mask64(x) ((__mmask64)(x))
#define _cvtmask32_u32(x) ((uint32_t)(x))
#define _cvtmask64_u64(x) ((uint64_t)(x))
#define _popcnt32(x) __builtin_popcount((unsigned)(x))
#define _popcnt64(x) __builtin_popcountll((unsigned long long)(x))
#define _mm512_broadcast_i64x2(a) simde_mm512_broadcast_i32x4(a)
#define _mm512_mask_sub_epi16(s,k,a,b) simde_mm512_mask_mov_epi16(s,k,simde_mm512_sub_epi16(a,b))
#define _mm512_maskz_sub_epi16(k,a,b) simde_mm512_maskz_mov_epi16(k,simde_mm512_sub_epi16(a,b))
static inline __m512i _mm512_mulhi_epu16(__m512i a, __m512i b) {
  uint16_t x[32],y[32],z[32]; __m512i r; memcpy(x,&a,64); memcpy(y,&b,64);
  for(int i=0;i<32;i++) z[i]=(uint16_t)(((uint32_t)x[i]*y[i])>>16);
  memcpy(&r,z,64); return r;
}
static inline __m512i _mm512_srai_epi64(__m512i a, unsigned shift) {
  int64_t x[8]; __m512i r; memcpy(x,&a,64); if(shift>63) shift=63;
  for(int i=0;i<8;i++) x[i] >>= shift;
  memcpy(&r,x,64); return r;
}
static inline __m512i _mm512_cvtepu32_epi64(__m256i a) {
  uint32_t x[8]; uint64_t y[8]; __m512i r; memcpy(x,&a,32);
  for(int i=0;i<8;i++) y[i]=x[i]; memcpy(&r,y,64); return r;
}
static inline __m512i _mm512_cvtepu8_epi64(__m128i a) {
  uint8_t x[16]; uint64_t y[8]; __m512i r; memcpy(x,&a,16);
  for(int i=0;i<8;i++) y[i]=x[i]; memcpy(&r,y,64); return r;
}
static inline __m512 _mm512_moveldup_ps(__m512 a) {
  uint32_t x[16],y[16]; __m512 r; memcpy(x,&a,64);
  for(int i=0;i<16;i++) y[i]=x[i&~1]; memcpy(&r,y,64); return r;
}
static inline __m512i _mm512_alignr_epi8(__m512i a, __m512i b, unsigned count) {
  uint8_t x[64],y[64],z[64]; __m512i r; memcpy(x,&a,64); memcpy(y,&b,64);
  for(int lane=0;lane<4;lane++) for(unsigned j=0;j<16;j++) {
    unsigned k=j+count; z[16*lane+j] = k<16 ? y[16*lane+k] : k<32 ? x[16*lane+k-16] : 0;
  }
  memcpy(&r,z,64); return r;
}
static inline __m512i _mm512_aesenc_epi128(__m512i a, __m512i b) {
  __m128i x[4],y[4],z[4]; __m512i r; memcpy(x,&a,64); memcpy(y,&b,64);
  for(int i=0;i<4;i++) z[i]=simde_mm_aesenc_si128(x[i],y[i]); memcpy(&r,z,64); return r;
}
static inline __m512i _mm512_aesenclast_epi128(__m512i a, __m512i b) {
  __m128i x[4],y[4],z[4]; __m512i r; memcpy(x,&a,64); memcpy(y,&b,64);
  for(int i=0;i<4;i++) z[i]=simde_mm_aesenclast_si128(x[i],y[i]); memcpy(&r,z,64); return r;
}
static inline __m128i _mm_aeskeygenassist_si128(__m128i a, unsigned rcon) {
  /* AES last round gives SubBytes+ShiftRows. Invert the row permutation for
     input words 1 and 3; generate SubWord and RotWord(SubWord)^rcon. */
  __m128i s=simde_mm_aesenclast_si128(a,simde_mm_setzero_si128());
  uint8_t x[16],y[16]; memcpy(x,&s,16);
  const unsigned indices[8]={4,1,14,11,12,9,6,3};
  for(int word=0;word<2;word++) {
    for(int j=0;j<4;j++) y[word*8+j]=x[indices[word*4+j]];
    for(int j=0;j<4;j++) y[word*8+4+j]=y[word*8+(j+1)%4];
    y[word*8+4]^=(uint8_t)rcon;
  }
  memcpy(&s,y,16); return s;
}

/* Reference code supplies runtime counts to an immediate-named intrinsic. */
#undef _mm512_srli_epi16
static inline __m512i _mm512_srli_epi16(__m512i a, unsigned shift) {
  uint16_t x[32]; __m512i r; memcpy(x,&a,64);
  for(int i=0;i<32;i++) x[i]=shift>15 ? 0 : (uint16_t)(x[i]>>shift);
  memcpy(&r,x,64); return r;
}
