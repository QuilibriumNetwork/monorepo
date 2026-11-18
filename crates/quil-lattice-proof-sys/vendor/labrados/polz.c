#include <stdint.h>
#include <limits.h>
#include <immintrin.h>
#include <math.h>
#include <stdio.h>
#include <assert.h>
#include "aesctr.h"
#include "data.h"
#include "polx.h"
#include "poly.h"
#include "polz.h"
#include "malloc.h"
#include "gaussian.h"

void polz_print(const polz a) {
  size_t i,j;

  for(i=0;i<N;i++) {
    printf("%2zu: ",i);
    printf("%5d",a->limbs[0]->c[i]);
    for(j=1;j<L;j++)
      printf(" + %5d * 2^%zu",a->limbs[j]->c[i],14*j);
    printf("\n");
  }
}

void polzvec_setzero(polz *r, size_t len) {
  polyvec_setzero(r[0]->limbs,1,L*len);
}

void polzvec_copy(polz *r, const polz *a, size_t len) {
  size_t i,j,k;
  __m512i f;

  for(i=0;i<len;i++) {
    for(j=0;j<L;j++) {
      for(k=0;k<N/32;k++) {
        f = _mm512_load_si512(&a[i]->limbs[j]->v[k]);
        _mm512_store_si512(&r[i]->limbs[j]->v[k],f);
      }
    }
  }
}

void polz_getcoeff(zz r, const polz a, int k) {
  size_t i;

  for(i=0;i<L;i++)
    r->limbs[i] = a->limbs[i]->c[k];
}

void polz_setcoeff(polz r, const zz a, int k) {
  size_t i;

  for(i=0;i<L;i++)
    r->limbs[i]->c[k] = a->limbs[i];
}

void polz_setcoeff_fromint64(polz r, int64_t a, int k) {
  size_t i;

  for(i=0;i<L-1;i++) {
    r->limbs[i]->c[k] = a & 0x3FFF;
    a >>= 14;
  }
 r->limbs[L-1]->c[k] = a;
}

void polzvec_fromint64vec(polz *r, size_t len, size_t deg, const int64_t v[len*deg*N]) {
  size_t i,j,k;

  for(i=0;i<len;i++)
    for(j=0;j<deg;j++)
      for(k=0;k<N;k++)
        polz_setcoeff_fromint64(r[i*deg+j],v[i*deg*N+k*deg+j],k);
}

int polz_iszero_constcoeff(const polz a) {
  size_t i;
  int64_t r;

  r = 0;
  for(i=0;i<L;i++)
    r |= (uint16_t)a->limbs[i]->c[0];

  r = -r >> 63;
  r += 1;
  return r;
}

// expects centered input
int polz_iszero(const polz a) {
  size_t i,j;
  int64_t r;

  r = 0;
  for(i=0;i<L;i++)
    for(j=0;j<N;j++)
      r |= (uint16_t)a->limbs[i]->c[j];

  r = -r >> 63;
  r += 1;
  return r;
}

int polzvec_iszero(const polz *a, size_t len) {
  size_t i;
  int64_t r;

  r = 0;
  for(i=0;i<len;i++)
    r += polz_iszero(a[i]);

  r -= len;
  r >>= 63;
  r += 1;
  return r;
}

static inline size_t uniform(zz r, const uint8_t *buf) {
  size_t i,j,s,bits;

  i = 0;
  s = 8;
  for(j=0;j<L;j++) {
    bits = (j < L-1) ? 14 : LOGQ - 14*(L-1);
    r->limbs[j] = (int16_t)buf[i] >> (8-s);
    while(s < bits) {
      r->limbs[j] |= (int16_t)buf[++i] << s;
      s += 8;
    }
    s = s - bits;
    r->limbs[j] &= (1 << bits) - 1;
  }

  if(zz_less_than(r,modulus->q))
    return 1;
  else
    return 0;
}

static void polzvec_uniform_stream(polz *r, size_t len, quil_prg_stream *stream) {
  size_t i,j,k;
  const size_t chunk = (4096/QUIL_PRG_BLOCKBYTES+QBYTES-1)/QBYTES*QUIL_PRG_BLOCKBYTES/N;
  size_t nblocks = chunk*N*QBYTES/QUIL_PRG_BLOCKBYTES;
  /* Limb-major output writes can overwrite unread samples when input aliases r. */
  __attribute__((aligned(64)))
  uint8_t buf[nblocks*QUIL_PRG_BLOCKBYTES];
  zz t;


  while(len >= chunk) {
    k = 0;
    quil_prg_squeeze(buf,nblocks,stream);
    for(i=0;i<chunk;i++) {
      for(j=0;j<N;j++) {
        k += uniform(t,&buf[(i*N+j)*QBYTES]);
        polz_setcoeff(r[i],t,j);
      }
    }

    if(k == chunk*N) {
      r += chunk;
      len -= chunk;
    }
  }

  quil_prg_clear(buf,sizeof(buf));
  while(len) {
    k = 0;
    nblocks = (len*N*QBYTES+QUIL_PRG_BLOCKBYTES-1)/QUIL_PRG_BLOCKBYTES;
    __attribute__((aligned(64)))
    uint8_t buf2[nblocks*QUIL_PRG_BLOCKBYTES];
    quil_prg_squeeze(buf2,nblocks,stream);
    for(i=0;i<len;i++) {
      for(j=0;j<N;j++) {
        k += uniform(t,&buf2[(i*N+j)*QBYTES]);
        polz_setcoeff(r[i],t,j);
      }
    }

    quil_prg_clear(buf2,sizeof(buf2));
    if(k == len*N)
      break;
  }
}

void polzvec_uniform(polz *r,size_t len,const uint8_t seed[SEEDLEN],uint64_t nonce) {
  aes256ctr_ctx state;
  aes256ctr_init(&state,seed,nonce);
  quil_prg_stream stream={&state,quil_prg_aes256_squeeze};
  polzvec_uniform_stream(r,len,&stream);
}
void quil_polzvec_uniform_private(polz *r,size_t len,const uint8_t seed[32],uint64_t nonce) {
  aes256ctr_ctx state;
  aes256ctr_init(&state,seed,nonce);
  quil_prg_stream stream={&state,quil_prg_aes256_squeeze};
  polzvec_uniform_stream(r,len,&stream);
  quil_prg_clear(&state,sizeof(state));
}

void polz_bitpack(uint8_t r[POLZBYTES], const polz a) {
  size_t i,j,k,bits;
  __m512i f,g,h;

  k = 0;
  h = _mm512_setzero_si512();
  for(i=0;i<L;i++) {
    bits = (i<L-1) ? 14 : LOGQ-14*(L-1);
    for(j=0;j<N/32;j++) {
      f = _mm512_load_si512(&a->limbs[i]->v[j]);
      g = _mm512_slli_epi16(f,k);
      h = _mm512_add_epi16(g,h);
      if(k >= 16-bits) {
        _mm512_storeu_si512(r,h);
        h = _mm512_srli_epi16(f,16-k);
        r += 64;
      }
      k = (k + bits) & 0xF;
    }
  }
  if(k)
    _mm512_storeu_si512(r,h);
}

void polzvec_bitpack(uint8_t *r, const polz *a, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    polz_bitpack(&r[i*POLZBYTES],a[i]);
}

void polz_bitunpack(polz r, const uint8_t buf[POLZBYTES]) {
  int i,j,k,bits;
  __m512i f,g,h,mask;
  const __m512i mask14 = _mm512_set1_epi16(0x3FFF);
  const __m512i maskhi = _mm512_srli_epi16(mask14,14*L-LOGQ);

  k = 0;
  h = _mm512_setzero_si512();
  for(i=0;i<L;i++) {
    if(i < L-1) {
      bits = 14;
      mask = mask14;
    }
    else {
      bits = LOGQ - 14*(L-1);
      mask = maskhi;
    }

    for(j=0;j<N/32;j++) {
      if(k < bits) {
        f = _mm512_load_si512((__m512i*)buf);
        g = _mm512_slli_epi16(f,k);
        h = _mm512_add_epi16(g,h);
        g = _mm512_and_si512(h,mask);
        h = _mm512_srli_epi16(f,bits-k);
        buf += 64;
      }
      else {
        g = _mm512_and_si512(h,mask);
        h = _mm512_srli_epi16(h,bits);
      }
      _mm512_store_si512(&r->limbs[i]->v[j],g);
      k = (k - bits) & 0xF;
    }
  }
}

void polzvec_almostuniform(polz *r, size_t len, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  size_t i;
  uint8_t *buf;
  size_t chunk,nblocks;
  aes256ctr_ctx aesctx;

  chunk = AES256CTR_BLOCKBYTES/64;
  nblocks = chunk*POLZBYTES/AES256CTR_BLOCKBYTES;
  aes256ctr_init(&aesctx,seed,nonce);

  while(len >= chunk) {
    buf = (uint8_t*)r + chunk*(N*2*L - POLZBYTES);
    aes256ctr_squeezeblocks(buf,nblocks,&aesctx);
    for(i=0;i<chunk;i++)
      polz_bitunpack(r[i],&buf[i*POLZBYTES]);
    len -= chunk;
    r += chunk;
  }

  if(len) {
    nblocks = (len*POLZBYTES+AES256CTR_BLOCKBYTES-1)/AES256CTR_BLOCKBYTES;
    __attribute__((aligned(64)))
    uint8_t buf2[nblocks*AES256CTR_BLOCKBYTES];
    aes256ctr_squeezeblocks(buf2,nblocks,&aesctx);
    for(i=0;i<len;i++)
      polz_bitunpack(r[i],&buf2[i*POLZBYTES]);
  }
}

double polzvec_norm(const polz *a, size_t len) {
  size_t i,j,k;
  long double r,t;
  long double q,hq;

  q = ldexpl(1,LOGQ) - QOFF;
  hq = (q-1)/2;

  r = 0;
  for(i=0;i<len;i++) {
    for(j=0;j<N;j++) {
      t = 0;
      for(k=0;k<L;k++)
        t += ldexpl(a[i]->limbs[k]->c[j],14*k);
      if(t > hq) t -= q;
      r += t*t;
    }
  }

  return sqrtl(r);
}

void polz_reduce(polz r) {
  size_t i,j;
  __m512i f,g,h;
  const __m512i qoff = _mm512_set1_epi16(QOFF);
  const __m512i qofft4 = _mm512_slli_epi16(qoff,2);
  const __m512i mask14 = _mm512_set1_epi16(0x3FFF);
  const __m512i maskhi = _mm512_srli_epi16(mask14,14*L-LOGQ);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&r->limbs[L-1]->v[i]);
    g = _mm512_srai_epi16(f,LOGQ-14*(L-1));
    f = _mm512_and_si512(f,maskhi);
    _mm512_store_si512(&r->limbs[L-1]->v[i],f);

    f = _mm512_load_si512(&r->limbs[0]->v[i]);
    h = _mm512_mullo_epi16(g,qoff);
    g = _mm512_mulhi_epi16(g,qofft4);
    h = _mm512_and_si512(h,mask14);
    f = _mm512_add_epi16(f,h);
    h = _mm512_srai_epi16(f,14);
    f = _mm512_and_si512(f,mask14);
    g = _mm512_add_epi16(g,h);
    _mm512_store_si512(&r->limbs[0]->v[i],f);

    for(j=1;j<L;j++) {
      f = _mm512_load_si512(&r->limbs[j]->v[i]);
      f = _mm512_add_epi16(f,g);
      if(j<L-1) {
        g = _mm512_srai_epi16(f,14);
        f = _mm512_and_si512(f,mask14);
      }
      _mm512_store_si512(&r->limbs[j]->v[i],f);
    }
  }
  // Canonical ring representatives before conversions reach transcript hashing.
  const int64_t q = ((int64_t)1 << LOGQ) - QOFF;
  for(i=0;i<N;i++) {
    zz coefficient;
    polz_getcoeff(coefficient,r,i);
    int64_t value = int64_fromzz(coefficient) % q;
    value += (value < 0) * q;
    polz_setcoeff_fromint64(r,value,i);
  }
}

void polzvec_reduce(polz *r, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    polz_reduce(r[i]);
}

void polz_caddq(polz r) {
  size_t i,j;
  __m512i f,c;
  __mmask32 mask;
  __m512i qq[L];
  const __m512i mask14 = _mm512_set1_epi16(0x3FFF);

  for(i=0;i<L;i++)
    qq[i] = _mm512_set1_epi16(modulus->q->limbs[i]);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&r->limbs[L-1]->v[i]);
    mask = _mm512_movepi16_mask(f);
    for(j=0;j<L;j++) {
      f = _mm512_load_si512(&r->limbs[j]->v[i]);
      f = _mm512_mask_add_epi16(f,mask,f,qq[j]);
      if(j > 0) f = _mm512_add_epi16(f,c);
      if(j < L-1) {
        c = _mm512_srai_epi16(f,14);
        f = _mm512_and_si512(f,mask14);
      }
      _mm512_store_si512(&r->limbs[j]->v[i],f);
    }
  }
}

void polzvec_caddq(polz *r, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    polz_caddq(r[i]);
}

void polz_center(polz r) {
#if defined(__aarch64__) && !defined(SIMDE_NO_NATIVE)
  int16x8_t qq[L],hq[L];
  const int16x8_t mask14=vdupq_n_s16(0x3fff);
  for(size_t j=0;j<L;j++)qq[j]=vdupq_n_s16(modulus->q->limbs[j]);
  for(size_t j=0;j<L-1;j++)
    hq[j]=vandq_s16(vaddq_s16(vreinterpretq_s16_u16(vshrq_n_u16(
        vreinterpretq_u16_s16(qq[j]),1)),vshlq_n_s16(qq[j+1],13)),mask14);
  hq[L-1]=vreinterpretq_s16_u16(vshrq_n_u16(vreinterpretq_u16_s16(qq[L-1]),1));
  for(size_t i=0;i<N;i+=8) {
    int16x8_t f=vdupq_n_s16(0),carry=vdupq_n_s16(0);
    for(size_t j=0;j<L;j++) {
      f=vsubq_s16(hq[j],vld1q_s16(&r->limbs[j]->c[i]));
      if(j)f=vaddq_s16(f,carry);
      if(j<L-1)carry=vshrq_n_s16(f,14);
    }
    const int16x8_t mask=vshrq_n_s16(f,15);
    for(size_t j=0;j<L;j++) {
      f=vsubq_s16(vld1q_s16(&r->limbs[j]->c[i]),vandq_s16(mask,qq[j]));
      if(j)f=vaddq_s16(f,carry);
      if(j<L-1){carry=vshrq_n_s16(f,14);f=vandq_s16(f,mask14);}
      vst1q_s16(&r->limbs[j]->c[i],f);
    }
  }
#else
  size_t i,j;
  __m512i f,c;
  __mmask32 mask;
  __m512i qq[L], hq[L];
  const __m512i mask14 = _mm512_set1_epi16(0x3FFF);

  for(i=0;i<L;i++)
    qq[i] = _mm512_set1_epi16(modulus->q->limbs[i]);
  for(i=0;i<L-1;i++) {
    hq[i] = _mm512_srli_epi16(qq[i],1);
    f = _mm512_slli_epi16(qq[i+1],13);
    hq[i] = _mm512_add_epi16(hq[i],f);
    hq[i] = _mm512_and_si512(hq[i],mask14);
  }
  hq[L-1] = _mm512_srli_epi16(qq[L-1],1);

  for(i=0;i<N/32;i++) {
    for(j=0;j<L;j++) {
      f = _mm512_load_si512(&r->limbs[j]->v[i]);
      f = _mm512_sub_epi16(hq[j],f);
      if(j > 0) f = _mm512_add_epi16(f,c);
      if(j < L-1) c = _mm512_srai_epi16(f,14);
    }
    mask = _mm512_movepi16_mask(f);

    for(j=0;j<L;j++) {
      f = _mm512_load_si512(&r->limbs[j]->v[i]);
      f = _mm512_mask_sub_epi16(f,mask,f,qq[j]);
      if(j > 0) f = _mm512_add_epi16(f,c);
      if(j < L-1) {
        c = _mm512_srai_epi16(f,14);
        f = _mm512_and_si512(f,mask14);
      }
      _mm512_store_si512(&r->limbs[j]->v[i],f);
    }
  }
#endif
}

void polzvec_center(polz *r, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    polz_center(r[i]);
}

void polz_topoly_montgomery(poly r, const polz a, const pdata prime) {
  size_t i,j;
  __m512i f,g,h;
  const __m512i pinvt4 = _mm512_slli_epi16(_mm512_set1_epi16(prime->pinv),2);
  const __m512i p = _mm512_set1_epi16(prime->p);

  for(i=0;i<N/32;i++) {
    g = _mm512_load_si512(&a->limbs[0]->v[i]);
    for(j=1;j<L;j++) {
      h = _mm512_mullo_epi16(g,pinvt4);
      f = _mm512_load_si512(&a->limbs[j]->v[i]);
      g = _mm512_srai_epi16(g,14);
      h = _mm512_mulhi_epu16(h,p);
      g = _mm512_add_epi16(f,g);
      g = _mm512_sub_epi16(g,h);
    }
    _mm512_store_si512(&r->v[i],g);
  }

  //Scaling factor multiplied during NTT
  //poly_scale(r,r,(1LL << (14*(L-1)+16)) % prime->p,prime);
}

void polzvec_topolyvec_montgomery(poly *r, const polz *a, ssize_t stride, size_t len, const pdata prime) {
  size_t i;

  for(i=0;i<len;i++)
    polz_topoly_montgomery(r[stride*i],a[i],prime);
}

void polz_topoly(poly r, const polz a) {
  size_t i;
  __m512i f;

  for(i=0;i<N/32;i++) {  //FIXME
    f = _mm512_load_si512(&a->limbs[0]->v[i]);
    _mm512_store_si512(&r->v[i],f);
  }
}

void polzvec_topolyvec(poly *r, const polz *a, ssize_t stride, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    polz_topoly(r[stride*i],a[i]);
}

void polz_frompoly(polz r, const poly a) {
  size_t i,j;
  __m512i f;
  const __m512i zero = _mm512_setzero_si512();

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->v[i]);
    _mm512_store_si512(&r->limbs[0]->v[i],f);
  }

  for(i=1;i<L;i++)
    for(j=0;j<N/32;j++)
      _mm512_store_si512(&r->limbs[i]->v[j],zero);
}

void polzvec_frompolyvec(polz *r, const poly *a, ssize_t stride, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    polz_frompoly(r[i],a[stride*i]);
}

void polz_topolx(polx r, const polz a) {
  size_t i;

  r->width = ldexp(1,2*LOGQ)/12.0;
  for(i=0;i<K;i++)
    polz_topoly_montgomery(r->proj[i],a,primes[i]);

  polx_ntt(r,r);
}

void polzvec_topolxvec(polxvec r, const polz *a, size_t off, ssize_t stride, size_t len) {
  size_t i,j,k;

  assert(off < r->len);
  assert(off+stride*(len-1) < r->len);
  polxvec_setwidths1(r,off,stride,len,ldexp(1,2*LOGQ)/12.0);
  off *= r->stride;
  stride *= r->stride;
  for(j=0;(k=MIN(32,len-j));j+=k) {
    for(i=0;i<K;i++) {
      polzvec_topolyvec_montgomery(&r->proj[i][off+j*stride],&a[j],stride,k,primes[i]);
      polyvec_ntt(&r->proj[i][off+stride*j],&r->proj[i][off+stride*j],stride,stride,k,primes[i]);
    }
  }
}

static void zz_poly_mul(polz r, const zz a, const poly b) {
  size_t i,j;
  int bits;
  __m512i e[L],f,ff;
  __m512i g,h,k,l;
  __m512i mask,qoff;

  for(i=0;i<L;i++)
    e[i] =  _mm512_set1_epi16(a->limbs[i]);  // 2^bits

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&b->v[i]);  // 2^14
    ff = _mm512_slli_epi16(f,2);  // 2^16

    bits = LOGQ - 14*(L-1);
    mask = _mm512_set1_epi16((1 << bits) - 1);
    h = _mm512_mullo_epi16(f,e[L-1]);  // 2^16
    g = _mm512_mulhi_epu16(f,e[L-1]);  // 2^(bits-2)
    k = _mm512_srli_epi16(h,bits);  // 2^(16-bits)
    g = _mm512_slli_epi16(g,16-bits);  // 2^14
    h = _mm512_and_si512(h,mask);  // 2^bits
    k = _mm512_add_epi16(k,g);  // 2^14
    _mm512_store_si512(&r->limbs[L-1]->v[i],h);  // 2^bits

    // Assumes L > 1
    bits = 14;
    mask = _mm512_set1_epi16(0x3FFF);
    qoff = _mm512_set1_epi16(QOFF);  // 2^13
    h = _mm512_mullo_epi16(f,e[0]);  // 2^16
    l = _mm512_mullo_epi16(qoff,k);  // 2^16
    qoff = _mm512_slli_epi16(qoff,2);  // 2^15
    g = _mm512_mulhi_epu16(ff,e[0]);  // 2^14
    k = _mm512_mulhi_epu16(qoff,k);  // 2^13
    h = _mm512_and_si512(h,mask);  // 2^14
    l = _mm512_and_si512(l,mask);  // 2^14
    h = _mm512_add_epi16(h,l);  // 2^15-1
    l = _mm512_srli_epi16(h,bits);  // 2
    h = _mm512_and_si512(h,mask);  // 2^14
    k = _mm512_add_epi16(k,g);  // 2^14+2^13-1
    k = _mm512_add_epi16(k,l);  // 2^14+2^13
    _mm512_store_si512(&r->limbs[0]->v[i],h);  // 2^14

    for(j=1;j<L-1;j++) {
      h = _mm512_mullo_epi16(f,e[j]);  // 2^16
      g = _mm512_mulhi_epu16(ff,e[j]);  // 2^13
      h = _mm512_and_si512(h,mask);  // 2^14
      h = _mm512_add_epi16(h,k);  // 2^15+2^13-2
      k = _mm512_srli_epi16(h,bits);  // 2+1
      h = _mm512_and_si512(h,mask);  // 2^14
      k = _mm512_add_epi16(k,g);  // 2^13+2
      _mm512_store_si512(&r->limbs[j]->v[i],h);  // 2^14
    }

    g = _mm512_load_si512(&r->limbs[L-1]->v[i]);  // 2^bits
    g = _mm512_add_epi16(g,k);  // 2^bits+2^14+2^13-1
    _mm512_store_si512(&r->limbs[L-1]->v[i],g);  // 2^bits+2^14+2^13-1
  }
}

static void zz_poly_fma(polz r, const zz a, const poly b) {
  size_t i,j;
  int bits;
  __m512i e[L],f,ff;
  __m512i g,h,k,l;
  __m512i mask,qoff;

  for(i=0;i<L;i++)
    e[i] = _mm512_set1_epi16(a->limbs[i]);  // 2^bits

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&b->v[i]);  // 2^14 (p_i)
    ff = _mm512_slli_epi16(f,2);  // 2^16

    bits = LOGQ - 14*(L-1);
    mask = _mm512_set1_epi16((1 << bits) - 1);
    h = _mm512_mullo_epi16(f,e[L-1]);  // 2^16
    g = _mm512_mulhi_epu16(f,e[L-1]);  // 2^(bits-2)
    k = _mm512_srli_epi16(h,bits);  // 2^(16-bits)
    g = _mm512_slli_epi16(g,16-bits);  // 2^14
    h = _mm512_and_si512(h,mask);  // 2^bits
    g = _mm512_add_epi16(g,k);  // 2^14
    k = _mm512_load_si512(&r->limbs[L-1]->v[i]);  // 2^bits+2^15
    h = _mm512_add_epi16(h,k);  // 2^(bits+1)+2^15-1
    k = _mm512_srli_epi16(h,bits);  // 2^(15-bits)+2
    h = _mm512_and_si512(h,mask);  // 2^bits
    k = _mm512_add_epi16(k,g);  // 2^14+2^12+1
    _mm512_store_si512(&r->limbs[L-1]->v[i],h);  // 2^bits

    bits = 14;
    qoff = _mm512_set1_epi16(QOFF);  // 2^13
    mask = _mm512_set1_epi16(0x3FFF);

    h = _mm512_mullo_epi16(f,e[0]);  // 2^16
    l = _mm512_mullo_epi16(qoff,k);  // 2^16
    qoff = _mm512_slli_epi16(qoff,2);  // 2^15
    g = _mm512_mulhi_epu16(ff,e[0]);  // 2^14
    k = _mm512_mulhi_epu16(qoff,k);  // 2^14
    h = _mm512_and_si512(h,mask);  // 2^14
    l = _mm512_and_si512(l,mask);  // 2^14
    h = _mm512_add_epi16(h,l);  // 2^15-1
    l = _mm512_load_si512(&r->limbs[0]->v[i]);  // 2^14
    h = _mm512_add_epi16(h,l);  // 2^15+2^14-2
    l = _mm512_srli_epi16(h,bits);  // 2+1
    h = _mm512_and_si512(h,mask);  // 2^14
    k = _mm512_add_epi16(k,g);  // 2^15-1
    k = _mm512_add_epi16(k,l);  // 2^15+1
    _mm512_store_si512(&r->limbs[0]->v[i],h);  // 2^14

    for(j=1;j<L-1;j++) {
      h = _mm512_mullo_epi16(f,e[j]);  // 2^16
      g = _mm512_mulhi_epu16(ff,e[j]);  // 2^14
      h = _mm512_and_si512(h,mask);  // 2^14
      h = _mm512_add_epi16(h,k);  // 2^15+2^14
      k = _mm512_load_si512(&r->limbs[j]->v[i]);  // 2^14
      h = _mm512_add_epi16(h,k);  // 2^16-1
      k = _mm512_srli_epi16(h,bits);  // 2^2
      h = _mm512_and_si512(h,mask);  // 2^14
      k = _mm512_add_epi16(k,g);  // 2^14+2^2-1
      _mm512_store_si512(&r->limbs[j]->v[i],h);  // 2^14
    }

    g = _mm512_load_si512(&r->limbs[L-1]->v[i]);  // 2^bits
    g = _mm512_add_epi16(g,k);  // 2^bits+2^15
    _mm512_store_si512(&r->limbs[L-1]->v[i],g);  // 2^bits+2^15
  }
}

/* Explicit CRT mod q:
 * a_i = a mod p_i, |a| <= (P-1)/2
 * t_i = (P/p_i)^-1 mod p_i
 * alpha_i = a_it_i mod p_i
 * Explicit CRT: a = (\sum_i alpha_i/p_i - round(\sum_i alpha_i/p_i))P
 * Explicit CRT mod q: \sum_i alpha_i(P/p_i mod q) - round(\sum_i alpha_i/p_i)(P mod q)
 */
void polz_frompolx(polz r, const polx a) {
  size_t i;
  polx b;
  poly k;
  __m512i f;
  const __m512i shift = _mm512_set1_epi16(1024);

  polx_invntt(b,a);
  polyvec_setzero(&k,0,1);
  for(i=0;i<K;i++) {
    poly_scale(b->proj[i],b->proj[i],primes[i]->t,primes[i]);  // alpha_i
    poly_caddp(b->proj[i],primes[i]);  // needed for higher precision
    poly_quot_add(k,b->proj[i],primes[i]);  // TODO: Overflow possible for K > 8
  }

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&k->v[i]);
    f = _mm512_add_epi16(f,shift);
    f = _mm512_srli_epi16(f,11);  // round(\sum_i alpha_i/p_i)
    _mm512_store_si512(&k->v[i],f);
  }

  zz_poly_mul(r,modulus->pmq,k);
  for(i=0;i<K;i++)
    zz_poly_fma(r,modulus->xvec[i],b->proj[i]);

  polz_reduce(r);
}

static void frompolxvec(polz *r, const polxvec a, size_t off, ssize_t stride, size_t len) {
  size_t i,j;
  poly b[K][len];
  poly k[len];
  __m512i f;
  const __m512i shift = _mm512_set1_epi16(1024);

  for(i=0;i<K;i++)
    polyvec_invntt(b[i],&a->proj[i][a->stride*off],1,a->stride*stride,len,primes[i]);
  polyvec_setzero(k,1,len);
  for(i=0;i<K;i++) {
    polyvec_scale(b[i],b[i],1,1,len,primes[i]->t,primes[i]);  // alpha_i
    polyvec_caddp(b[i],1,len,primes[i]);  // needed for higher precision
    polyvec_quot_add(k,b[i],1,1,len,primes[i]);  // TODO: Overflow possible for K > 8
  }

  for(i=0;i<len;i++) {
    for(j=0;j<N/32;j++) {
      f = _mm512_load_si512(&k[i]->v[j]);
      f = _mm512_add_epi16(f,shift);
      f = _mm512_srli_epi16(f,11);  // round(\sum_i alpha_i/p_i)
      _mm512_store_si512(&k[i]->v[j],f);
    }
  }

#if defined(__aarch64__) && !defined(SIMDE_NO_NATIVE) && LOGQ == 38 && K == 6 && L == 3
  /* Fixed-profile exact CRT sum. The original inverse transforms, scaling,
   * positive residues and quotient rounding above are unchanged. With seven
   * weights below 2^38 and uint16 coefficients, the sum is < 2^57. */
  const uint64_t q=(UINT64_C(1)<<38)-107;
  uint64_t weights[K+1];
  int usable=1;
  for(size_t term=0;term<K+1;term++) {
    const struct zz_str *weight=term ? modulus->xvec[term-1] : modulus->pmq;
    if(weight->limbs[0]<0 || weight->limbs[0]>=16384 ||
       weight->limbs[1]<0 || weight->limbs[1]>=16384 ||
       weight->limbs[2]<0 || weight->limbs[2]>=1024) {
      usable=0;
      break;
    }
    weights[term]=(uint64_t)weight->limbs[0]+((uint64_t)weight->limbs[1]<<14)
                  +((uint64_t)weight->limbs[2]<<28);
    if(weights[term]>=q){usable=0;break;}
  }
  if(usable) {
    for(i=0;i<len;i++)for(size_t c=0;c<N;c++) {
      uint64_t sum=(uint16_t)k[i]->c[c]*weights[0];
      for(j=0;j<K;j++)sum+=(uint16_t)b[j][i]->c[c]*weights[j+1];
      uint64_t reduced=sum%q;
      r[i]->limbs[0]->c[c]=(int16_t)(reduced&16383);
      r[i]->limbs[1]->c[c]=(int16_t)((reduced>>14)&16383);
      r[i]->limbs[2]->c[c]=(int16_t)(reduced>>28);
    }
    return;
  }
#endif
  for(i=0;i<len;i++) {
    zz_poly_mul(r[i],modulus->pmq,k[i]);
    for(j=0;j<K;j++)
      zz_poly_fma(r[i],modulus->xvec[j],b[j][i]);
  }

  polzvec_reduce(r,len);
}

void polzvec_frompolxvec(polz *r, const polxvec a, size_t off, ssize_t stride, size_t len) {
  size_t j,k;

  assert(off < a->len);
  assert(off+stride*(len-1) < a->len);
  for(j=0;(k=MIN(32,len-j));j+=k)
    frompolxvec(&r[j],a,off+j*stride,stride,k);
}

void polz_add(polz r, const polz a, const polz b) {
  size_t i,j;
  __m512i f,g,c;
  const __m512i mask14 = _mm512_set1_epi16(0x3FFF);

  for(i=0;i<N/32;i++) {
    for(j=0;j<L;j++) {
      f = _mm512_load_si512(&a->limbs[j]->v[i]);
      g = _mm512_load_si512(&b->limbs[j]->v[i]);
      f = _mm512_add_epi16(f,g);
      if(j > 0) f = _mm512_add_epi16(f,c);
      if(j < L-1) {
        c = _mm512_srai_epi16(f,14);
        f = _mm512_and_si512(f,mask14);
      }
      _mm512_store_si512(&r->limbs[j]->v[i],f);
    }
  }
}

void polzvec_add(polz *r, const polz *a, const polz *b, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    polz_add(r[i],a[i],b[i]);
}

void polz_sub(polz r, const polz a, const polz b) {
  size_t i,j;
  __m512i f,g,c;
  const __m512i mask14 = _mm512_set1_epi16(0x3FFF);

  for(i=0;i<N/32;i++) {
    for(j=0;j<L;j++) {
      f = _mm512_load_si512(&a->limbs[j]->v[i]);
      g = _mm512_load_si512(&b->limbs[j]->v[i]);
      f = _mm512_sub_epi16(f,g);
      if(j > 0) f = _mm512_add_epi16(f,c);
      if(j < L-1) {
        c = _mm512_srai_epi16(f,14);
        f = _mm512_and_si512(f,mask14);
      }
      _mm512_store_si512(&r->limbs[j]->v[i],f);
    }
  }
}

void polzvec_sub(polz *r, const polz *a, const polz *b, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    polz_sub(r[i],a[i],b[i]);
}

void polz_slli(polz r, const polz a, int s) {
  size_t i,j;
  __m512i f,g,h;
  const __m512i mask14 = _mm512_set1_epi16(0x3FFF);

  for(i=0;i<N/32;i++) {
    for(j=0;j<L;j++) {
      f = _mm512_load_si512(&a->limbs[j]->v[i]);
      g = _mm512_slli_epi16(f,s);
      if(j) g = _mm512_add_epi16(g,h);
      if(j<L-1) {
        g = _mm512_and_si512(g,mask14);
        h = _mm512_srai_epi16(f,14-s);
      }
      _mm512_store_si512(&r->limbs[j]->v[i],g);
    }
  }
}

void polzvec_slli(polz *r, const polz *a, size_t len, int s) {
  size_t i;

  for(i=0;i<len;i++)
    polz_slli(r[i],a[i],s);
}

void polz_mul(polz r, const polz a, const polz b) {
  polx f,g;

  polz_topolx(f,a);
  polz_topolx(g,b);
  polx_mul(f,f,g);
  polz_frompolx(r,f);
}

void polz_poly_mul(polz r, const polz a, const poly b) {
  polx f,g;

  polz_topolx(f,a);
  polx_frompoly(g,b,ldexp(1,28)/12.0);
  polx_mul(f,f,g);
  polz_frompolx(r,f);
}

// expects centered input
void polz_split(poly lo, polz hi, const polz a, size_t d) {
  size_t i,j;
  __m512i f,g,h;
  const __m512i mask14 = _mm512_set1_epi16(0x3FFF);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->limbs[0]->v[i]);
    g = _mm512_slli_epi16(f,16-d);
    g = _mm512_srai_epi16(g,16-d);  // mod 2^d sign extended
    _mm512_store_si512(&lo->v[i],g);
    f = _mm512_sub_epi16(f,g);  // zero mod 2^d
    f = _mm512_srai_epi16(f,d);
    for(j=0;j<L-1;j++) {
      g = _mm512_load_si512(&a->limbs[j+1]->v[i]);
      h = _mm512_slli_epi16(g,14-d);
      h = _mm512_and_si512(h,mask14);
      f = _mm512_add_epi16(f,h);
      h = _mm512_srai_epi16(f,14);  // carry
      f = _mm512_and_si512(f,mask14);
      _mm512_store_si512(&hi->limbs[j]->v[i],f);
      f = _mm512_srai_epi16(g,d);
      f = _mm512_add_epi16(f,h);
    }
    _mm512_store_si512(&hi->limbs[L-1]->v[i],f);
  }
}

void polzvec_split(poly *lo, polz *hi, const polz *a, ssize_t stride, size_t len, size_t d) {
  size_t i;

  for(i=0;i<len;i++)
    polz_split(lo[stride*i],hi[i],a[i],d);
}

/* Expects centered input */
void polz_bindec(poly *r, const polz a, ssize_t stride, size_t t) {
  size_t i,j,k,s;
  __m512i f,g;
  const __m512i mask = _mm512_set1_epi16(1);

  for(i=0;i<N/32;i++) {
    k = s = 0;
    for(j=0;j<t;j++) {
      if(!s) {
        f = _mm512_load_si512(&a->limbs[k++]->v[i]);
        s = 14;
      }
      g = _mm512_and_si512(f,mask);
      f = _mm512_srai_epi16(f,1);
      _mm512_store_si512(&r[stride*j]->v[i],g);
      s -= 1;
    }
  }
}

void polzvec_bindec(poly *r, const polz *a, size_t len, ssize_t stride, size_t t) {
  size_t i;

  assert(stride >= (ssize_t)len);
  for(i=0;i<len;i++)
    polz_bindec(&r[i],a[i],stride,t);
}

void polz_bindec_topolxvec(polxvec r, const polz a, ssize_t stride, size_t t) {
  poly b[t];
  polxvec rs;

  polz_bindec(b,a,1,t);
  polxvec_init_subvec2(rs,r,0,stride,t);
  polxvec_frompolyvec(rs,b,1,t,1/2.0);
}

void polzvec_bindec_topolxvec(polxvec r, const polz *a, size_t len, ssize_t stride, size_t t) {
  size_t i,j,k;
  poly b[32*t];
  polxvec rs;

  assert(stride >= (ssize_t)len);
  assert(r->len == t*stride);
  for(j=0;(k=MIN(32,len-j));j+=k) {
    polzvec_bindec(b,&a[j],k,k,t);
    for(i=0;i<t;i++) {
      polxvec_init_subvec2(rs,r,stride*i+j,1,k);
      polxvec_frompolyvec(rs,&b[i*k],1,k,1/2.0);
    }
  }
  if((ssize_t)len < stride)
    for(i=0;i<t;i++)
      polxvec_setzero(r,stride*i+len,1,stride-len);
}

/* Expects centered input */
void polz_decompose(poly *r, const polz a, ssize_t stride, size_t t, size_t d) {
  size_t i,j,k,s;
  __m512i f,g,h;
  const __m512i mask = _mm512_set1_epi16((1<<d) - 1);

  for(i=0;i<N/32;i++) {
    f = _mm512_load_si512(&a->limbs[0]->v[i]);
    k = 1;
    s = 14;
    for(j=0;j<t-1;j++) {
      if(s < d && k < L) {
        g = _mm512_load_si512(&a->limbs[k++]->v[i]);
        h = _mm512_slli_epi16(g,s);
        h = _mm512_and_si512(h,mask);
        f = _mm512_add_epi16(f,h);
        h = _mm512_slli_epi16(f,16-d);
        h = _mm512_srai_epi16(h,16-d);  // mod 2^d sign extended
        _mm512_store_si512(&r[stride*j]->v[i],h);
        f = _mm512_sub_epi16(f,h);  // zero mod 2^d
        f = _mm512_srai_epi16(f,d);
        g = _mm512_srai_epi16(g,d-s);
        f = _mm512_add_epi16(f,g);
        s += 14-d;
      }
      else {
        g = _mm512_slli_epi16(f,16-d);
        g = _mm512_srai_epi16(g,16-d);  // mod 2^d sign extended
        _mm512_store_si512(&r[stride*j]->v[i],g);
        f = _mm512_sub_epi16(f,g);  // zero mod 2^d
        f = _mm512_srai_epi16(f,d);
        s -= d;
      }
    }

    if(k < L) {
      g = _mm512_load_si512(&a->limbs[k++]->v[i]);
      g = _mm512_slli_epi16(g,s);
      f = _mm512_add_epi16(f,g);
      f = _mm512_slli_epi16(f,2);
      f = _mm512_srai_epi16(f,2);
    }
    _mm512_store_si512(&r[stride*(t-1)]->v[i],f);
  }
}

void polzvec_decompose(poly *r, const polz *a, size_t len, ssize_t stride, size_t t, size_t d) {
  size_t i;

  if(0 && t==1) {  // FIXME: why did it work before?
    polzvec_topolyvec(r,a,1,len);
    return;
  }

  if(stride >= (ssize_t)len) {
    for(i=0;i<len;i++)
      polz_decompose(&r[i],a[i],stride,t,d);
  }
  else {
    for(i=0;i<len;i++)
      polz_decompose(&r[t*stride*i],a[i],stride,t,d);
  }
}

void polz_decompose_topolxvec(polxvec r, const polz a, ssize_t stride, size_t t, size_t d) {
  poly b[t];
  polxvec rs;

  assert(r->len >= t*stride);
  polz_decompose(b,a,1,t,d);
  polxvec_init_subvec2(rs,r,0,stride,t);
  polxvec_frompolyvec(rs,b,1,t,ldexp(1,2*d)/12);
}

void polzvec_decompose_topolxvec(polxvec r, const polz *a, size_t len, ssize_t stride, size_t t, size_t d) {
  size_t i,j,k;
  double width;
  poly b[32*t];
  polxvec rs;

  assert(stride >= (ssize_t)len);
  width = ldexp(1,2*d)/12;
  for(j=0;(k=MIN(32,len-j));j+=k) {
    polzvec_decompose(b,&a[j],k,k,t,d);
    for(i=0;i<t;i++) {
      polxvec_init_subvec2(rs,r,stride*i+j,1,k);
      polxvec_frompolyvec(rs,&b[k*i],1,k,width);
    }
  }
  if((ssize_t)len < stride)
    for(i=0;i<t;i++)
      polxvec_setzero(r,stride*i+len,1,stride-len);
}

void polz_reconstruct(polz r, const poly *a, ssize_t stride, size_t t, size_t d) {
  size_t i,j,k,s;
  __m512i f,g,h;
  const __m512i mask = _mm512_set1_epi16(0x3FFF);

  for(i=0;i<N/32;i++) {
    h = _mm512_setzero_si512();
    k = s = 0;
    for(j=0;j<L;j++) {
      while(k < t && (j == L-1 || s < 14-d)) {
        f = _mm512_load_si512(&a[stride*k++]->v[i]);
        f = _mm512_slli_epi16(f,s);
        h = _mm512_add_epi16(h,f);
        s += d;
      }  // k == t || (j < L-1 && 14-d <= s < 14)
      if(k < t) {
        f = _mm512_load_si512(&a[stride*k++]->v[i]);
        g = _mm512_slli_epi16(f,s);
        g = _mm512_and_si512(g,mask);
        h = _mm512_add_epi16(h,g);
        g = _mm512_and_si512(h,mask);
        _mm512_store_si512(&r->limbs[j]->v[i],g);
        h = _mm512_srai_epi16(h,14);
        g = _mm512_srai_epi16(f,14-s);
        h = _mm512_add_epi16(h,g);
        s -= 14-d;
      }  // k == t || 0 <= s < d
      else if(j < L-1) {
        g = _mm512_and_si512(h,mask);
        _mm512_store_si512(&r->limbs[j]->v[i],g);
        h = _mm512_srai_epi16(h,14);
      }
      else
        _mm512_store_si512(&r->limbs[j]->v[i],h);
    }
  }
}

void polzvec_reconstruct(polz *r, const poly *a, size_t len, ssize_t stride, size_t t, size_t d) {
  size_t i;

  if(t==1) {
    polzvec_frompolyvec(r,a,1,len);
    return;
  }

  for(i=0;i<len;i++)
    polz_reconstruct(r[i],&a[i],stride,t,d);
}

void polz_sigmam1(polz r, const polz a) {
  polyvec_sigmam1(r->limbs,a->limbs,1,1,L);
}

void polzvec_sigmam1(polz *r, const polz *a, size_t len) {
  polyvec_sigmam1(r[0]->limbs,a[0]->limbs,1,1,L*len);
}

void polz_printint64(const polz a) {
  size_t i;
  zz coeff;
  int64_t tmp;

  for(i=0;i<N;i++) {
    polz_getcoeff(coeff, a, i);
    tmp = int64_fromzz(coeff);
    printf("%2zu: %ld\n",i,tmp);
  }
}

int64_t polzvec_sprodz(const polz *a, const polz *b, size_t len) {
  zz coeffa, coeffb;
  int64_t sum, ia, ib;
  size_t i, j;

  sum = 0;
  for (i = 0; i < len; i++) {
    for(j = 0; j < N; j++) {
      polz_getcoeff(coeffa, a[i], j);
      polz_getcoeff(coeffb, b[i], j);
      
      ia = int64_fromzz(coeffa);
      ib = int64_fromzz(coeffb);

      sum += ia * ib;
    }
  }
  return sum;
}

static int polzvec_gaussian_stream(polz *r, size_t len, unsigned int log2sd,
                                    quil_prg_stream *stream) {
  int64_t tmp;
  int32_t *coeffs;
  size_t i, j;

  if(log2sd>26 || len>UINT_MAX/N || len>SIZE_MAX/(N*sizeof(int32_t)) || (len && !r))return -1;
  if(!len)return 0;
  coeffs = _malloc (N * len * sizeof(int32_t));

  int status=quil_gaussian_i32_stream(coeffs, N * len, stream, log2sd);
  if(status) { quil_prg_clear(coeffs,N*len*sizeof(*coeffs));free(coeffs);return status; }

  for (i = 0; i < len; i++) {
    for (j = 0; j < N; j++) {
      tmp = coeffs[i * N + j];
      polz_setcoeff_fromint64(r[i], tmp, j);
    }
  }

  quil_prg_clear(coeffs,N*len*sizeof(*coeffs));
  free (coeffs);
  return 0;
}
void polzvec_gaussian(polz *r,size_t len,unsigned int log2sd,const uint8_t seed[SEEDLEN],uint64_t nonce) {
  aes256ctr_ctx state;
  aes256ctr_init(&state,seed,nonce);
  quil_prg_stream stream={&state,quil_prg_aes256_squeeze};
  if(polzvec_gaussian_stream(r,len,log2sd,&stream))abort();
}
int quil_polzvec_gaussian_private(polz *r,size_t len,unsigned int log2sd,const uint8_t seed[32],uint64_t nonce) {
  if(log2sd>26 || len>QUIL_PRIVATE_GAUSSIAN_MAX_COEFFICIENTS/N || (len && !r))return -1;
  if(!len)return 0;
  int32_t *coeffs=_malloc(N*len*sizeof(*coeffs));
  int status=quil_gaussian_private_i32(coeffs,N*len,seed,nonce,log2sd);
  if(!status) {
    for(size_t i=0;i<len;i++)for(size_t j=0;j<N;j++)
      polz_setcoeff_fromint64(r[i],coeffs[i*N+j],j);
  }
  quil_prg_clear(coeffs,N*len*sizeof(*coeffs));
  free(coeffs);
  return status;
}
