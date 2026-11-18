#include <stddef.h>
#include <stdint.h>
#include <math.h>
#include <assert.h>
#include "data.h"
#include "malloc.h"
#include "polx.h"
#include "poly.h"
#include "polz.h"

static int64_t cmodq(int64_t a) {
  int64_t t;
  const int64_t mask = ((int64_t)1 << LOGQ) - 1;
  const int64_t q = ((int64_t)1 << LOGQ) - QOFF;

  t = a >> LOGQ;
  a &= mask;
  a += t*QOFF;
  t = q/2 - a;
  a -= (t >> 63)&q;
  return a;
}

void polxvec_init(polxvec r, size_t len, int widths) {
  size_t i;
  void *buf;

  r->alloc = r->len = len;
  r->off = 0;
  r->stride = 1;
  buf = _aligned_alloc(64,len*K*sizeof(poly));
  for(i=0;i<K;i++) {
    r->proj[i] = buf;
    buf = &r->proj[i][len];
  }
  if(widths)
    r->widths = _malloc(len*sizeof(double));
  else
    r->widths = NULL;
}

void polxvec_init_subvec(polxvec r, const polxvec a, size_t off, ssize_t stride, size_t len) {
  size_t i;

  assert(off < a->alloc);

  for(i=0;i<K;i++)
    r->proj[i] = &a->proj[i][off-a->off];
  r->widths = (a->widths) ? &a->widths[off-a->off] : NULL;

  r->alloc = a->alloc;
  r->off = off;
  r->stride = stride;
  if(len)
    r->len = len;
  else if(stride >= 0)
    r->len = (r->alloc-off)/stride;
  else
    r->len = off/-stride;

  assert(off + stride*(r->len-1) < r->alloc);
}

void polxvec_init_subvec2(polxvec r, const polxvec a, size_t off, ssize_t stride, size_t len) {
  size_t i;

  assert(off < a->len);

  for(i=0;i<K;i++)
    r->proj[i] = &a->proj[i][a->stride*off];
  r->widths = (a->widths) ? &a->widths[a->stride*off] : NULL;

  r->alloc = a->alloc;
  r->off = off = a->off + a->stride*off;
  r->stride = stride = stride*a->stride;
  if(len)
    r->len = len;
  else if(stride >= 0)
    r->len = (r->alloc-off)/stride;
  else
    r->len = off/-stride;
  assert(off + stride*(r->len-1) < r->alloc);
}

void polxvec_init_frompolx(polxvec r, polx a) {
  size_t i;

  r->alloc = 0;
  r->off = 0;
  r->stride = 0;
  r->len = 1;
  r->widths = (a->width == MAXWIDTH) ? NULL : &a->width;
  for(i=0;i<K;i++)
    r->proj[i] = &a->proj[i];
}

void polxvec_free(polxvec r) {
  if(!r->alloc) return;
  free(&r->proj[0][-r->off]);
  free(&r->widths[-r->off]);
  r->alloc = 0;
}

void polxvec_setwidths1(polxvec r, size_t off, ssize_t stride, size_t len, double width) {
  size_t i;

  if(!r->widths)
    return;

  assert(width < MAXWIDTH);
  assert(off < r->len);
  if(!len && stride >= 0)
    len = (r->len-off)/stride;
  else if(!len)
    len = off/-stride;
  assert(off + stride*(len-1) < r->len);
  off *= r->stride;
  stride *= r->stride;
  for(i=0;i<len;i++)
    r->widths[off+i*stride] = width;
}

static void polxvec_copywidths(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len >= a->len);
  assert(!r->widths || a->widths);
  if(!r->widths)
    return;
  for(i=0;i<a->len;i++)
    r->widths[i*r->stride] = a->widths[i*a->stride];
}

void polx_print(const polx a) {
  polz t;

  polz_frompolx(t,a);
  polz_center(t);
  polz_print(t);
}

void polxvec_print(const polxvec a, size_t off, ssize_t stride, size_t len) {
  size_t i;
  polz t;

  assert(off < a->len);
  if(!len && stride >= 0)
    len = (a->len-off)/stride;
  else if(!len)
    len = off/-stride;
  assert(off + stride*(len-1) < a->len);
  for(i=0;i<len;i++) {
    polzvec_frompolxvec(&t,a,off+i*stride,0,1);
    polz_center(t);
    polz_print(t);
  }
}

void polx_getcoeff(zz r, const polx a, int k) {
  polz t;

  polz_frompolx(t,a);
  polz_getcoeff(r,t,k);
}

void polxvec_getcoeff(zz r, const polxvec a, size_t j, int k) {
  polz t;

  assert(a->len > j);
  polzvec_frompolxvec(&t,a,j,1,1);
  polz_getcoeff(r,t,k);
}

void polx_setzero(polx r) {
  r->width = 0;
  polyvec_setzero(&r->proj[0],1,K);
}

void polxvec_setzero(polxvec r, size_t off, ssize_t stride, size_t len) {
  size_t i;

  assert(off < r->len);
  if(!len && stride >= 0)
    len = (r->len-off)/stride;
  else if(!len)
    len = off/-stride;
  assert(off + stride*(len-1) < r->len);
  polxvec_setwidths1(r,off,stride,len,0);
  off *= r->stride;
  stride *= r->stride;

  for(i=0;i<K;i++)
    polyvec_setzero(&r->proj[i][off],stride,len);
}

int polx_iszero(const polx a) {
  polz t;

  polz_frompolx(t,a);
  polz_center(t);
  return polz_iszero(t);
}

int polxvec_iszero(const polxvec a) {
  size_t j,k;
  int64_t r = 0;
  polz t[32];

  for(j=0;(k=MIN(32,a->len-j));j+=k) {
    polzvec_frompolxvec(t,a,j,1,k);
    polzvec_center(t,k);
    r += polzvec_iszero(t,k);
  }

  r -= (a->len+31)/32;
  r >>= 63;
  r += 1;
  return r;
}

int polx_iszero_constcoeff(const polx a) {
  polz t;

  polz_frompolx(t,a);
  polz_center(t);
  return polz_iszero_constcoeff(t);
}

int polxvec_iszero_constcoeff(const polxvec a, size_t j) {
  polz t;

  assert(a->len > j);
  polzvec_frompolxvec(&t,a,j,0,1);
  polz_center(t);
  return polz_iszero_constcoeff(t);
}

void polx_copy(polx r, const polx a){
  size_t i;

  r->width = a->width;
  for(i=0;i<K;i++)
    polyvec_copy(&r->proj[i],&a->proj[i],0,0,1);
}

void polxvec_copy(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len >= a->len);
  polxvec_copywidths(r,a);
  for(i=0;i<K;i++)
    polyvec_copy(r->proj[i],a->proj[i],r->stride,a->stride,a->len);
}

void polx_monomial(polx r, int k, int64_t v) {
  size_t i;

  v = cmodq(v);
  r->width = (double)v*v/N;
  for(i=0;i<K;i++)
    poly_monomial_ntt(r->proj[i],modp(v,primes[i]),k,primes[i]);
}

void polxvec_monomial(polxvec r, size_t j, int k, int64_t v) {
  size_t i;

  assert(r->len > j);
  v = cmodq(v);
  r->widths[j] = (double)v*v/N;
  for(i=0;i<K;i++)
    poly_monomial_ntt(r->proj[i][j*r->stride],modp(v,primes[i]),k,primes[i]);
}

void polx_fromint64vec(polx r, const int64_t *a, double width) {
  size_t i;

  assert(width <= MAXWIDTH);
  r->width = width;
  for(i=0;i<K;i++) {
    polyvec_fromint64vec(&r->proj[i],a,0,1,1,primes[i]);
    poly_scale(r->proj[i],r->proj[i],primes[i]->s,primes[i]);
    poly_ntt(r->proj[i],r->proj[i],primes[i]);
  }
}

void polxvec_fromint64vec(polxvec r, const int64_t *a, size_t len, size_t deg, double width) {
  size_t i,j,k;

  assert(r->len >= len*deg);
  polxvec_setwidths1(r,0,1,len*deg,width);
  for(j=0;(k=MIN(32,len-j));j+=k) {
    for(i=0;i<K;i++) {
      polyvec_fromint64vec(&r->proj[i][r->stride*j*deg],&a[j*deg*N],r->stride,k,deg,primes[i]);
      polyvec_scale(&r->proj[i][r->stride*j*deg],&r->proj[i][r->stride*j*deg],
                    r->stride,r->stride,k*deg,primes[i]->s,primes[i]);
      polyvec_ntt(&r->proj[i][r->stride*j*deg],&r->proj[i][r->stride*j*deg],r->stride,r->stride,k*deg,primes[i]);
    }
  }
}

void polxvec_fromint64vec2(polxvec r, const int64_t *a, size_t len, size_t deg, double width) {
  polz t[len*deg];

  polzvec_fromint64vec(t,len,deg,a);
  polzvec_topolxvec(r,t,0,1,len*deg);
  polxvec_setwidths1(r,0,1,len,width);
}

void polx_frompoly(polx r, const poly a, double width) {
  size_t i;

  assert(width <= MAXWIDTH);
  r->width = width;
  for(i=0;i<K;i++)
    poly_scale(r->proj[i],a,primes[i]->s,primes[i]);
  polx_ntt(r,r);
}

void polxvec_frompolyvec(polxvec r, const poly *a, ssize_t stride, size_t len, double width) {
  size_t i,j,k;

  assert(r->len >= len);
  polxvec_setwidths1(r,0,1,len,width);
  for(j=0;(k=MIN(32,len-j));j+=k) {
    for(i=0;i<K;i++) {
      polyvec_scale(&r->proj[i][j*r->stride],&a[j*stride],r->stride,stride,k,primes[i]->s,primes[i]);
      polyvec_ntt(&r->proj[i][j*r->stride],&r->proj[i][j*r->stride],r->stride,r->stride,k,primes[i]);
    }
  }
}

void polx_frompolxvec(polx r, const polxvec a, size_t j) {
  size_t i;

  assert(j < a->len);
  r->width = a->widths ? a->widths[j] : MAXWIDTH;
  for(i=0;i<K;i++)
    polyvec_copy(&r->proj[i],&a->proj[i][j*a->stride],0,0,1);
}

void polx_almostuniform(polx r, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  size_t i;
  polz t;

  r->width = ldexp(1,2*LOGQ)/12.0;
  polzvec_almostuniform(&t,1,seed,nonce);
  polz_center(t);  // FIXME: Performance?
  for(i=0;i<K;i++) {
    polz_topoly_montgomery(r->proj[i],t,primes[i]);
    poly_ntt(r->proj[i],r->proj[i],primes[i]);
  }
}

void polxvec_almostuniform(polxvec r, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  size_t i,j,k;
  polz t[32];

  polxvec_setwidths1(r,0,1,r->len,ldexp(1,2*LOGQ)/12.0);
  for(j=0;(k=MIN(32,r->len-j));j+=k) {
    polzvec_almostuniform(t,k,seed,nonce);
    polzvec_center(t,k);  // FIXME: Performance?
    nonce += (uint64_t)1 << 32;
    for(i=0;i<K;i++) {
      polzvec_topolyvec_montgomery(&r->proj[i][j*r->stride],t,r->stride,k,primes[i]);
      polyvec_ntt(&r->proj[i][j*r->stride],&r->proj[i][j*r->stride],r->stride,r->stride,k,primes[i]);
    }
  }
}

void polx_ternary(polx r, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  polyvec_ternary(&r->proj[K-1],0,1,seed,nonce);
  polx_frompoly(r,r->proj[K-1],10/16.0);
}

void polxvec_ternary(polxvec r, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  polyvec_ternary(r->proj[K-1],r->stride,r->len,seed,nonce);
  polxvec_frompolyvec(r,r->proj[K-1],r->stride,r->len,10/16.0);
}

void polx_quarternary(polx r, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  polyvec_quarternary(&r->proj[K-1],0,1,seed,nonce);
  polx_frompoly(r,r->proj[K-1],1.5);
}

void polxvec_quarternary(polxvec r, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  polyvec_quarternary(r->proj[K-1],r->stride,r->len,seed,nonce);
  polxvec_frompolyvec(r,r->proj[K-1],r->stride,r->len,1.5);
}

void polx_challenge(polx r, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  polyvec_challenge(&r->proj[K-1],0,1,seed,nonce);
  polx_frompoly(r,r->proj[K-1],(double)(TAU1+4*TAU2)/N);
}

void polxvec_challenge(polxvec r, const uint8_t seed[SEEDLEN], uint64_t nonce) {
  polyvec_challenge(r->proj[K-1],r->stride,r->len,seed,nonce);
  polxvec_frompolyvec(r,r->proj[K-1],r->stride,r->len,(double)(TAU1+4*TAU2)/N);
}

void polx_refresh(polx r) {
  polz t;

  polz_frompolx(t,r);
  polz_center(t);
  polz_topolx(r,t);
}

void polxvec_refresh(polxvec r) {
  size_t j,k;
  polz t[32];

  for(j=0;(k=MIN(32,r->len-j));j+=k) {
    polzvec_frompolxvec(t,r,j,1,k);
    polzvec_center(t,k);
    polzvec_topolxvec(r,t,j,1,k);
  }
}

void polx_reduce(polx r) {
  size_t i;

  for(i=0;i<K;i++)
    poly_reduce(r->proj[i],primes[i]);
}

void polxvec_reduce(polxvec r) {
  size_t i;

  for(i=0;i<K;i++)
    polyvec_reduce(r->proj[i],r->stride,r->len,primes[i]);
}

void polx_neg(polx r, const polx a) {
  size_t i;

  r->width = a->width;
  for(i=0;i<K;i++)
    poly_neg(r->proj[i],a->proj[i]);
}

void polxvec_neg(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len == a->len);
  polxvec_copywidths(r,a);
  for(i=0;i<K;i++)
    polyvec_neg(r->proj[i],a->proj[i],r->stride,a->stride,a->len);
}

void polx_add(polx r, const polx a, const polx b) {
  size_t i;

  r->width = a->width + b->width;
  assert(r->width <= MAXWIDTH);
  for(i=0;i<K;i++)
    poly_add(r->proj[i],a->proj[i],b->proj[i]);
  polx_reduce(r);
}

void polxvec_add(polxvec r, const polxvec a, const polxvec b) {
  size_t i,j,k;

  assert(r->len == a->len && a->len == b->len);
  assert(!r->widths || (a->widths && b->widths));
  if(r->widths) {
    for(i=0;i<r->len;i++) {
      double aw = a->widths[i*a->stride], bw = b->widths[i*b->stride];
      if (!(aw+bw <= MAXWIDTH)) fprintf(stderr,"WIDTH_ADD a=%.17g b=%.17g len=%zu i=%zu offsets=%zu,%zu,%zu strides=%zd,%zd,%zd\n",aw,bw,r->len,i,r->off,a->off,b->off,r->stride,a->stride,b->stride);
      r->widths[i*r->stride] = aw + bw;
      assert(r->widths[i*r->stride] <= MAXWIDTH);
    }
  }
  for(j=0;(k=MIN(32,r->len-j));j+=k) {
    for(i=0;i<K;i++) {
      polyvec_add(&r->proj[i][j*r->stride],&a->proj[i][j*a->stride],&b->proj[i][j*b->stride],
                  r->stride,a->stride,b->stride,k);
      polyvec_reduce(&r->proj[i][j*r->stride],r->stride,k,primes[i]);
    }
  }
}

void polx_sub(polx r, const polx a, const polx b) {
  size_t i;

  r->width = a->width + b->width;
  assert(r->width <= MAXWIDTH);
  for(i=0;i<K;i++)
    poly_sub(r->proj[i],a->proj[i],b->proj[i]);
  polx_reduce(r);
}

void polxvec_sub(polxvec r, const polxvec a, const polxvec b) {
  size_t i,j,k;

  assert(r->len == a->len && a->len == b->len);
  assert(!r->widths || (a->widths && b->widths));
  if(r->widths) {
    for(i=0;i<r->len;i++) {
      r->widths[i*r->stride] = a->widths[i*a->stride] + b->widths[i*b->stride];
      assert(r->widths[i*r->stride] <= MAXWIDTH);
    }
  }
  for(j=0;(k=MIN(32,r->len-j));j+=k) {
    for(i=0;i<K;i++) {
      polyvec_sub(&r->proj[i][j*r->stride],&a->proj[i][j*a->stride],&b->proj[i][j*b->stride],
                  r->stride,a->stride,b->stride,k);
      polyvec_reduce(&r->proj[i][j*r->stride],r->stride,k,primes[i]);
    }
  }
}

void polx_ntt(polx r, const polx a) {
  size_t i;

  for(i=0;i<K;i++)
    poly_ntt(r->proj[i],a->proj[i],primes[i]);
}

void polxvec_ntt(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len == a->len);
  for(i=0;i<K;i++)
    polyvec_ntt(r->proj[i],a->proj[i],r->stride,a->stride,r->len,primes[i]);
}

void polx_invntt(polx r, const polx a) {
  size_t i;

  for(i=0;i<K;i++)
    poly_invntt(r->proj[i],a->proj[i],primes[i]);
}

void polxvec_invntt(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len == a->len);
  for(i=0;i<K;i++)
    polyvec_invntt(r->proj[i],a->proj[i],r->stride,a->stride,r->len,primes[i]);
}

void polxvec_ntt_interleaved_half(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len == 2*a->len);
  if(r->widths) {
    for(i=0;i<r->len;i++) {
      r->widths[i*r->stride] = 0;  // FIXME
      assert(r->widths[i*r->stride] <= MAXWIDTH);
    }
  }
  for(i=0;i<K;i++)
    polyvec_ntt_interleaved_half(r->proj[i],a->proj[i],r->stride,a->stride,r->len,primes[i]);
}

void polxvec_invntt_interleaved(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len == a->len);
  if(r->widths) {
    for(i=0;i<r->len;i++) {
      r->widths[i*r->stride] = 0;  // FIXME
      assert(r->widths[i*r->stride] <= MAXWIDTH);
    }
  }
  for(i=0;i<K;i++)
    polyvec_invntt_interleaved(r->proj[i],a->proj[i],r->stride,a->stride,r->len,primes[i]);
}

void polx_mul(polx r, const polx a, const polx b) {
  size_t i;

  r->width = N*a->width*b->width;
  assert(r->width <= MAXWIDTH);
  for(i=0;i<K;i++)
    poly_pointwise(r->proj[i],a->proj[i],b->proj[i],primes[i]);
}

void polx_poly_mul(polx r, const polx a, const poly b, double width) {
  polx t;

  polx_frompoly(t,b,width);
  polx_mul(r,a,t);
}

void polxvec_mul(polxvec r, const polxvec a, const polxvec b) {
  size_t i;

  if(a->len == 1) {
    assert(r->len == b->len);
    assert(!r->widths || (a->widths && b->widths));
    if(r->widths) {
      for(i=0;i<r->len;i++) {
        r->widths[i*r->stride] = N*a->widths[0]*b->widths[i*b->stride];
        assert(r->widths[i*r->stride] <= MAXWIDTH);
      }
    }
    for(i=0;i<K;i++)
      polyvec_poly_pointwise(r->proj[i],*a->proj[i],b->proj[i],r->stride,b->stride,r->len,primes[i]);
  }
  else {
    assert(r->len == a->len && a->len == b->len);
    assert(!r->widths || (a->widths && b->widths));
    if(r->widths) {
      for(i=0;i<r->len;i++) {
        r->widths[i*r->stride] = N*a->widths[i*a->stride]*b->widths[i*b->stride];
        assert(r->widths[i*r->stride] <= MAXWIDTH);
      }
    }
    for(i=0;i<K;i++)
      polyvec_pointwise(r->proj[i],a->proj[i],b->proj[i],r->stride,a->stride,b->stride,r->len,primes[i]);
  }
}

void polxvec_polx_mul(polxvec r, polx a, const polxvec b) {
  polxvec aa;

  polxvec_init_frompolx(aa,a);
  polxvec_mul(r,aa,b);
}

void polx_mul_add(polx r, const polx a, const polx b) {
  size_t i;

  r->width += N*a->width*b->width;
  assert(r->width <= MAXWIDTH);
  for(i=0;i<K;i++)
    poly_pointwise_add(r->proj[i],a->proj[i],b->proj[i],primes[i]);
  polx_reduce(r);
}

void polxvec_mul_add(polxvec r, const polxvec a, const polxvec b) {
  size_t i,j,k;

  if(a->len == 1) {
    assert(r->len == b->len);
    assert(!r->widths || (a->widths && b->widths));
    if(r->widths) {
      for(i=0;i<r->len;i++) {
        size_t ai = (a->len == 1) ? 0 : i*a->stride;
        if(!(r->widths[i*r->stride] + N*a->widths[ai]*b->widths[i*b->stride] <= MAXWIDTH)) {
          polxvec_refresh(r);
          break;
        }
      }
      for(i=0;i<b->len;i++) {
        r->widths[i*r->stride] += N*a->widths[0]*b->widths[i*b->stride];
        assert(r->widths[i*r->stride] <= MAXWIDTH);
      }
    }
    for(j=0;(k=MIN(32,b->len-j));j+=k) {
      for(i=0;i<K;i++) {
        polyvec_poly_pointwise_add(&r->proj[i][j*r->stride],*a->proj[i],&b->proj[i][j*b->stride],
                                   r->stride,b->stride,k,primes[i]);
        polyvec_reduce(&r->proj[i][j*r->stride],r->stride,k,primes[i]);
      }
    }
  }
  else {
    assert(r->len == a->len && a->len == b->len);
    assert(!r->widths || (a->widths && b->widths));
    if(r->widths) {
      for(i=0;i<r->len;i++) {
        size_t ai = (a->len == 1) ? 0 : i*a->stride;
        if(!(r->widths[i*r->stride] + N*a->widths[ai]*b->widths[i*b->stride] <= MAXWIDTH)) {
          polxvec_refresh(r);
          break;
        }
      }
      for(i=0;i<b->len;i++) {
        r->widths[i*r->stride] += N*a->widths[i*a->stride]*b->widths[i*b->stride];
        assert(r->widths[i*r->stride] <= MAXWIDTH);
      }
    }
    for(j=0;(k=MIN(32,a->len-j));j+=k) {
      for(i=0;i<K;i++) {
        polyvec_pointwise_add(&r->proj[i][j*r->stride],&a->proj[i][j*a->stride],&b->proj[i][j*b->stride],
                              r->stride,a->stride,b->stride,k,primes[i]);
        polyvec_reduce(&r->proj[i][j*r->stride],r->stride,k,primes[i]);
      }
    }
  }
}

void polxvec_polx_mul_add(polxvec r, polx a, const polxvec b) {
  polxvec aa;

  polxvec_init_frompolx(aa,a);
  polxvec_mul_add(r,aa,b);
}

void polxvec_sprod(polxvec r, const polxvec a, const polxvec b) {
  size_t i;

  assert(r->len == 1);
  assert(a->len == b->len);
  assert(r->widths || (a->widths && b->widths));
  if(a->len == 0) {
    polxvec_setzero(r,0,0,1);
    return;
  }
  if(r->widths) {
    *r->widths = 0;
    for(i=0;i<a->len;i++)
      *r->widths += N*a->widths[i*a->stride]*b->widths[i*b->stride];
    assert(*r->widths <= MAXWIDTH);
  }
  for(i=0;i<K;i++)
    polyvec_sprod_pointwise(*r->proj[i],a->proj[i],b->proj[i],a->stride,b->stride,a->len,primes[i]);
}

void polxvec_sprod_add(polxvec r, const polxvec a, const polxvec b) {
  size_t i;

  assert(r->len == 1);
  assert(a->len == b->len);
  assert(r->widths || (a->widths && b->widths));
  if(r->widths) {
    double next_width = *r->widths;
    for(i=0;i<a->len;i++) next_width += N*a->widths[i*a->stride]*b->widths[i*b->stride];
    if(!(next_width <= MAXWIDTH)) polxvec_refresh(r);
    for(i=0;i<a->len;i++)
      *r->widths += N*a->widths[i*a->stride]*b->widths[i*b->stride];
    assert(*r->widths <= MAXWIDTH);
  }
  for(i=0;i<K;i++)
    polyvec_sprod_pointwise_add(*r->proj[i],a->proj[i],b->proj[i],a->stride,b->stride,a->len,primes[i]);
  polxvec_reduce(r);
}

void polx_scale(polx r, const polx a, int64_t s) {
  size_t i;

  s = cmodq(s);
  r->width = (double)s*s*a->width;
  assert(r->width <= MAXWIDTH);
  s <<= 16;  // Montgomery factor
  for(i=0;i<K;i++)
    poly_scale(r->proj[i],a->proj[i],modp(s,primes[i]),primes[i]);
}

void polx_scale_frompoly(polx r, const poly a, double width, int64_t s) {
  size_t i;

  s = cmodq(s);
  r->width = (double)s*s*width;
  assert(r->width <= MAXWIDTH);
  for(i=0;i<K;i++)
    poly_scale(r->proj[i],a,modp(s*primes[i]->s,primes[i]),primes[i]);
  polx_ntt(r,r);
}

void polxvec_scale(polxvec r, const polxvec a, int64_t s) {
  size_t i;

  s = cmodq(s);
  assert(r->len == a->len);
  assert(!r->widths || a->widths);
  if(r->widths) {
    for(i=0;i<r->len;i++) {
      r->widths[i*r->stride] = (double)s*s*a->widths[i*a->stride];
      assert(r->widths[i*r->stride] <= MAXWIDTH);
    }
  }
  s <<= 16;
  for(i=0;i<K;i++)
    polyvec_scale(r->proj[i],a->proj[i],r->stride,a->stride,r->len,modp(s,primes[i]),primes[i]);
}

void polxvec_scale_frompolyvec(polxvec r, const poly *a, ssize_t stride, size_t len, double width, int64_t s) {
  size_t i,j,k;
  int16_t sp[K];

  assert(r->len == len);
  polxvec_setwidths1(r,0,1,len,(double)s*s*width);
  s = cmodq(s);
  for(i=0;i<K;i++)
    sp[i] = modp(s*primes[i]->s,primes[i]);
  for(j=0;(k=MIN(32,len-j));j+=k) {
    for(i=0;i<K;i++) {
      polyvec_scale(&r->proj[i][j*r->stride],&a[j*stride],r->stride,stride,k,sp[i],primes[i]);
      polyvec_ntt(&r->proj[i][j*r->stride],&r->proj[i][j*r->stride],r->stride,r->stride,k,primes[i]);
    }
  }
}

void polx_scale_add(polx r, const polx a, int64_t s) {
  size_t i;

  s = cmodq(s);
  r->width += (double)s*s*a->width;
  assert(r->width <= MAXWIDTH);
  s <<= 16;
  for(i=0;i<K;i++)
    poly_scale_add(r->proj[i],a->proj[i],modp(s,primes[i]),primes[i]);
  polx_reduce(r);
}

void polxvec_scale_add(polxvec r, const polxvec a, int64_t s) {
  size_t i,j,k;
  int16_t sp[K];

  assert(r->len == a->len);
  assert(!r->widths || a->widths);
  s = cmodq(s);
  if(r->widths) {
    // Normalize the valid accumulator before its next addition would overflow.
    // An oversized individual term still fails the original assertion below.
    for(i=0;i<r->len;i++) {
      if(!(r->widths[i*r->stride]+(double)s*s*a->widths[i*a->stride] <= MAXWIDTH)) {
        polxvec_refresh(r);
        break;
      }
    }
    for(i=0;i<r->len;i++) {
      r->widths[i*r->stride] += (double)s*s*a->widths[i*a->stride];
      assert(r->widths[i*r->stride] <= MAXWIDTH);
    }
  }
  s <<= 16;
  for(i=0;i<K;i++)
    sp[i] = modp(s,primes[i]);
  for(j=0;(k=MIN(32,r->len-j));j+=k) {
    for(i=0;i<K;i++) {
      polyvec_scale_add(&r->proj[i][j*r->stride],&a->proj[i][j*a->stride],r->stride,a->stride,k,sp[i],primes[i]);
      polyvec_reduce(&r->proj[i][j*r->stride],r->stride,k,primes[i]);
    }
  }
}

static size_t polxvec_sprod_extension_internal(polxvec c, const polxvec a, const polxvec b, int add) {
  size_t i,j,k;
  size_t deg;
  size_t off_a = 0;
  double width_a,width_b,width_c;
  poly tmp[c->len];

  deg = next2power(c->len);
  k  = extlen(b->len,deg);
  assert(a->len >= off_a+k);
  assert(!c->widths || (a->widths && b->widths));
  if(c->widths) {
    width_c = 0;
    for(i=0;i<b->len;i+=deg) {
      width_a = width_b = 0;
      for(j=0;j<deg;j++) {
         width_a += a->widths[(off_a+i+j)*a->stride];
         width_b += (i+j < b->len) ? b->widths[(i+j)*b->stride] : 0;
      }
      width_c += width_a*width_b;
    }
    width_c *= N/deg;
    if (!(width_c <= MAXWIDTH)) fprintf(stderr,"WIDTH_SPROD width=%.17g a=%zu b=%zu c=%zu deg=%zu add=%d\n",width_c,a->len,b->len,c->len,deg,add);
    if(!add) {
      assert(width_c <= MAXWIDTH);
      for(i=0;i<c->len;i++)
        c->widths[i*c->stride] = width_c;
    }
    else {
      for(i=0;i<c->len;i++) {
        c->widths[i*c->stride] += width_c;
        assert(c->widths[i*c->stride] <= MAXWIDTH);
      }
    }
  }
  for(i=0;i<K;i++) {
    if(!add)
      polyvec_sprod_extension(c->proj[i],a->proj[i],b->proj[i],
                              c->stride,a->stride,b->stride,deg,c->len,b->len,primes[i]);
    else {
      polyvec_sprod_extension(tmp,&a->proj[i][off_a*a->stride],b->proj[i],
                              1,a->stride,b->stride,deg,c->len,b->len,primes[i]);
      polyvec_add(c->proj[i],c->proj[i],tmp,c->stride,c->stride,1,c->len);  // TODO: better rely on interleave_reduce_add in sprod_extension
      polyvec_reduce(c->proj[i],c->stride,c->len,primes[i]);
    }
  }
  return k;
}

size_t polxvec_sprod_extension(polxvec c, const polxvec a, const polxvec b){
  return polxvec_sprod_extension_internal(c, a, b, 0);
}

size_t polxvec_sprod_extension_add(polxvec c, const polxvec a, const polxvec b){
  return polxvec_sprod_extension_internal(c, a, b, 1);
}

size_t polxvec_collaps_add_extension(polxvec c, const polxvec b, const polxvec a, size_t off_a) {
  size_t i,j,k;
  size_t deg;
  double width_a,width_b,width_c;

  deg = next2power(b->len);
  k  = extlen(c->len,deg);
  assert(a->len >= off_a+k);
  assert(!c->widths || (a->widths && b->widths));
  if(c->widths) {
    width_b = 0;
    for(i=0;i<b->len;i++)
      width_b += b->widths[i*b->stride];
    for(i=0;i<c->len;i+=deg) {
      width_a = 0;
      for(j=0;j<deg;j++)
         width_a += a->widths[(off_a+i+j)*a->stride];
      width_c = width_a*width_b*N/deg;
      for(j=0;j<MIN(deg,c->len-i);j++) {
        c->widths[(i+j)*c->stride] += width_c;
        assert(c->widths[(i+j)*c->stride] <= MAXWIDTH);
      }
    }
  }
  for(i=0;i<K;i++)
    polyvec_collaps_add_extension(c->proj[i],b->proj[i],&a->proj[i][off_a*a->stride],
                                  c->stride,b->stride,a->stride,deg,c->len,b->len,primes[i]);
  return k;
}

size_t polxvec_pairwise_mul(polxvec h, const polxvec a) {
  size_t i;
  const size_t r = a->len;
  const size_t m = (r*r+r)/2;

  assert(h->len == m);
  if(h->widths) {
    for(i=0;i<m;i++) {
      h->widths[i*h->stride] = 0;  //FIXME
      assert(h->widths[i*h->stride] <= MAXWIDTH);
    }
  }
  for(i=0;i<K;i++)
    polyvec_pairwise_pointwise(h->proj[i],a->proj[i],a->proj[i],h->stride,a->stride,a->stride,r,r,primes[i]);
  return m;
}

size_t polxvec_pairwise_sprod(polxvec g, const polxvec a, const polxvec b, size_t r, size_t n) {
  size_t i;
  const size_t m = (r*r+r)/2;

  assert(g->len == m);
  assert(a->len == r*n && b->len == r*n);
  if(g->widths) {
    for(i=0;i<m;i++) {
      g->widths[i*g->stride] = 0;  //FIXME
      assert(g->widths[i*g->stride] <= MAXWIDTH);
    }
  }
  for(i=0;i<K;i++)
    polyvec_pairwise_sprod(g->proj[i],a->proj[i],b->proj[i],r,n,primes[i]);
  return m;
}

void polx_bindec(poly *r, const polx a, ssize_t stride, size_t t) {
  polz b;

  polz_frompolx(b,a);
  polz_center(b);
  polz_bindec(r,b,stride,t);
}

void polxvec_bindec(poly *r, const polxvec a, ssize_t stride, size_t t) {
  size_t j,k;
  polz b[32];

  assert(stride >= (ssize_t)a->len);
  for(j=0;(k=MIN(32,a->len-j));j+=k) {
    polzvec_frompolxvec(b,a,j,1,k);
    polzvec_center(b,k);
    polzvec_bindec(&r[j],b,k,stride,t);
  }
}

void polx_decompose(poly *r, const polx a, ssize_t stride, size_t t, size_t d) {
  polz b;

  polz_frompolx(b,a);
  polz_center(b);
  polz_decompose(r,b,stride,t,d);
}

void polxvec_decompose(poly *r, const polxvec a, ssize_t stride, size_t t, size_t d) {
  size_t j,k;
  polz b[32];

  assert(stride >= (ssize_t)a->len);
  for(j=0;(k=MIN(32,a->len-j));j+=k) {
    polzvec_frompolxvec(b,a,j,1,k);
    polzvec_center(b,k);
    polzvec_decompose(&r[j],b,k,stride,t,d);
  }
}

void polx_reconstruct(polx r, const poly *a, ssize_t stride, size_t t, size_t d) {
  polz b;

  polz_reconstruct(b,a,stride,t,d);
  polz_topolx(r,b);
}

void polxvec_reconstruct(polxvec r, const poly *a, ssize_t stride, size_t t, size_t d) {
  size_t j,k;
  polz b[32];

  //polxvec_setwidths1(r,0,r->len,ldexp(1,2*d*t)/12.0);
  for(j=0;(k=MIN(32,r->len-j));j+=k) {
    polzvec_reconstruct(b,&a[j],k,stride,t,d);
    polzvec_topolxvec(r,b,j,1,k);
  }
}

void polx_sigmam1(polx r, const polx a) {
  size_t i;

  r->width = a->width;
  for(i=0;i<K;i++)
    poly_sigmam1_ntt(r->proj[i],a->proj[i]);
}

void polxvec_sigmam1(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len == a->len);
  polxvec_copywidths(r,a);
  for(i=0;i<K;i++)
    polyvec_sigmam1_ntt(r->proj[i],a->proj[i],r->stride,a->stride,r->len);
}

/* FIXME: NTT rep! */
void polx_sigma5(polx r, const polx a) {
  size_t i;

  r->width = a->width;
  for(i=0;i<K;i++)
    poly_sigma5(r->proj[i],a->proj[i]);
}

void polxvec_sigma5(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len == a->len);
  polxvec_copywidths(r,a);
  for(i=0;i<K;i++)
    polyvec_sigma5(r->proj[i],a->proj[i],r->stride,a->stride,r->len);
}

void polx_sigma5inv(polx r, const polx a) {
  size_t i;

  r->width = a->width;
  for(i=0;i<K;i++)
    poly_sigma5inv(r->proj[i],a->proj[i]);
}

void polxvec_sigma5inv(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len == a->len);
  polxvec_copywidths(r,a);
  for(i=0;i<K;i++)
    polyvec_sigma5(r->proj[i],a->proj[i],r->stride,a->stride,r->len);
}

void polx_flip(polx r, const polx a) {
  size_t i;

  r->width = 1 + a->width;
  for(i=0;i<K;i++)
    poly_flip_ntt(r->proj[i],a->proj[i],primes[i]);
}

void polxvec_flip(polxvec r, const polxvec a) {
  size_t i;

  assert(r->len == a->len);
  assert(!r->widths || a->widths);
  if(r->widths) {
    for(i=0;i<r->len;i++)
      r->widths[r->stride*i] = 1 + a->widths[a->stride*i];
  }
  for(i=0;i<K;i++)
    polyvec_flip_ntt(r->proj[i],a->proj[i],r->stride,a->stride,r->len,primes[i]);
}
