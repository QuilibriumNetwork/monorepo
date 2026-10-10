#ifndef DATA_H
#define DATA_H

#define N 256
#ifndef LOGQ
#define LOGQ 38
#endif
#define QBYTES ((LOGQ+7)/8)
#define POLZBYTES ((N/32*LOGQ+15)/16*64)
/* Root-Hermite target for every internal M-SIS instance: block size 483,
 * 2^128 quantum core-SVP (2^141 classical). Was 1.00444 (2^91 quantum). */
#define LOGDELTA log2(1.003489)
/* Transcript chaining state and public expansion seeds: 32 bytes, so the
 * Fiat-Shamir state is a 2^128 quantum preimage target and the public PRG is
 * AES-256. */
#define HASHLEN 32
#define SEEDLEN 32
#define LIFTS ((128+LOGQ-1)/LOGQ)
#define SLACK 2

#if N == 64
#define TAU1 32
#define TAU2 8
#define T 14  // challenge operator norm
#elif N == 128
#define TAU1 30
#define TAU2 0
#define T 14 // FIXME
#elif N == 256
#define TAU1 24 // challenge support 2^135.4 before operator-norm filtering (22: 2^126.7)
#define TAU2 0
#define T 10 // operator-norm bound; acceptance ~13% at TAU1 24
#else
#error
#endif

#if LOGQ == 32
#define QOFF 99
#define K 6
#define L 3
#define MAXWIDTH 1.5e+46
#define NAMESPACE(s) labrador32_##s
#elif LOGQ == 36
#define QOFF 243
#define K 6
#define L 3
#define MAXWIDTH 1.5e+46
#define NAMESPACE(s) labrador36_##s
#elif LOGQ == 38
#define QOFF 107
#define K 6
#define L 3
#define MAXWIDTH 1.5e+46
#define NAMESPACE(s) labrador38_##s
#else
#error
#endif

#ifndef __ASSEMBLER__

#include <stdint.h>
#include <stddef.h>
#include <immintrin.h>

#define MIN(a,b) (((a) <= (b)) ? (a) : (b))
#define MIN3(a,b,c) (MIN(MIN(a,b),c)
#define MAX(a,b) (((a) >= (b)) ? (a) : (b))

union vecn {
  __m512i v[N/32];
  int16_t c[N];
};

struct pdata_str {
  int16_t p;         // 12 < log2(p) < 14
  int16_t pinv;      // p^-1 mod 2^16
  int16_t mont;      // mont = 2^16 mod p
  int16_t mont_pinv; // mont_pinv = pinv*mont mod 2^16
  int16_t i;         // i = mont*sqrt(-1) mod p
  int16_t i_pinv;    // i_pinv = pinv*i mod 2^16
  int16_t s;         // s = mont*2^(-14*(L-1)) mod p
  int16_t f;         // f = montsq*2^(14*(L-1))*2^(16*(log(N)-1)) mod p
  int16_t f_pinv;    // f_pinv = pinv*f mod 2^16
  int16_t t;         // t = (P/p)^-1*2^(15*log(N)) mod p
  int16_t u;         // u = 2^(-28*(L-1))*2^(15*log(N)) mod p
  int16_t v;         // v = round(2^27/p)
  int64_t v64;       // v = round(2^75/p)
  union vecn zetas[1];
  union vecn zetas_pinv[1];
};

typedef const struct pdata_str *pdata_ptr;
typedef struct pdata_str pdata[1];

extern const pdata primes[K];

typedef struct zz_str {
  int16_t limbs[L];
} zz[1];

typedef struct qdata_str {
  zz q;
  zz pmq;
  zz xvec[K];
} qdata[1];

static void zz_copy(zz r, const zz a) {
  size_t i;

  for(i=0;i<L;i++)
    r->limbs[i] = a->limbs[i];
}

static void zz_fromint64(zz r, int64_t a) {
  size_t i;

  for(i=0;i<L-1;i++) {
    r->limbs[i] = a & 0x3FFF;
    a >>= 14;
  }
  r->limbs[L-1] = a;
}

static int64_t int64_fromzz(zz coeff) {
  int64_t r;
  int i;

  r = coeff->limbs[0];
  for (i = 1; i < L; i++) {
    r = r + (int64_t)coeff->limbs[i] * ((int64_t)1 << (14 * i));
  }
  return r;
}

static int zz_less_than(const zz a, const zz b) {
  int i;
  int16_t c = 0;

  for(i=0;i<L;i++)
    c = (a->limbs[i] - b->limbs[i] + c) >> 14;

  return c;
}

static int zz_equal(const zz a, const zz b) {
  int i;
  int16_t c = 0;
  int16_t r = 0;

  for(i=0;i<L;i++) {
    c = a->limbs[i] - b->limbs[i] + c;
    r |= c;
    c >>= 14;
  }

  r |= c;
  r &= 0x3FFF;
  r  = -r >> 15;
  r += 1;
  return r;
}

static void zz_add(zz r, const zz a, const zz b) {
  size_t i;
  int16_t c;

  c = 0;
  for(i=0;i<L-1;i++) {
    r->limbs[i] = a->limbs[i] + b->limbs[i] + c;
    c = r->limbs[i] >> 14;
    r->limbs[i] &= 0x3FFF;
  }
  r->limbs[L-1] = a->limbs[L-1] + b->limbs[L-1] + c;
}

static void zz_sub(zz r, const zz a, const zz b) {
  size_t i;
  int16_t c;

  c = 0;
  for(i=0;i<L-1;i++) {
    r->limbs[i] = a->limbs[i] - b->limbs[i] + c;
    c = r->limbs[i] >> 14;
    r->limbs[i] &= 0x3FFF;
  }
  r->limbs[L-1] = a->limbs[L-1] - b->limbs[L-1] + c;
}

extern const qdata modulus;

#else
#define _P 0
#define _PINV 1
#define _MONT 2
#define _MONT_PINV 3
#define _I 4
#define _I_PINV 5
#define _S 6
#define _F 7
#define _F_PINV 8
#define _T 9
#define _U 10
#define _V 11
#define _V64 12
#define _ZETAS 16
#define _ZETAS_PINV 272

#endif
#endif
