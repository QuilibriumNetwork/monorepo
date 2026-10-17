#ifndef POLZ_H
#define POLZ_H

#include <stdint.h>
#include <immintrin.h>
#include "data.h"
#include "polx.h"
#include "poly.h"

struct polz_str {
  poly limbs[L];
};

typedef struct polz_str polz[1];
typedef struct polz_str *polz_ptr;

void polz_print(const polz a);
void polz_printint64(const polz a);
void polz_getcoeff(zz r, const polz a, int k);
void polz_setcoeff(polz r, const zz a, int k);
void polz_setcoeff_fromint64(polz r, int64_t a, int k);

int polz_iszero(const polz a);
int polz_iszero_constcoeff(const polz a);
int polzvec_iszero(const polz *a, size_t len);
double polzvec_norm(const polz *a, size_t len);

void polzvec_setzero(polz *r, size_t len);
void polzvec_copy(polz *r, const polz *a, size_t len);
void polzvec_fromint64vec(polz *r, size_t len, size_t deg, const int64_t v[len*deg*N]);  // FIXME

void polzvec_uniform(polz *r, size_t len, const uint8_t seed[SEEDLEN], uint64_t nonce);
void quil_polzvec_uniform_private(polz *r, size_t len, const uint8_t seed[32], uint64_t nonce);
void polzvec_almostuniform(polz *r, size_t len, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polz_bitpack(uint8_t r[POLZBYTES], const polz a);
void polzvec_bitpack(uint8_t *r, const polz *a, size_t len);
void polz_bitunpack(polz r, const uint8_t buf[POLZBYTES]);

void polz_reduce(polz r);
void polzvec_reduce(polz *r, size_t len);
void polz_caddq(polz r);
void polzvec_caddq(polz *r, size_t len);
void polz_center(polz r);
void polzvec_center(polz *r, size_t len);

void polz_topoly_montgomery(poly r, const polz a, const pdata prime);
void polzvec_topolyvec_montgomery(poly *r, const polz *a, ssize_t stride, size_t len, const pdata prime);
void polz_topoly(poly r, const polz a);
void polzvec_topolyvec(poly *r, const polz *a, ssize_t stride, size_t len);
void polz_frompoly(polz r, const poly a);
void polzvec_frompolyvec(polz *r, const poly *a, ssize_t stride, size_t len);
void polz_topolx(polx r, const polz a);
void polzvec_topolxvec(polxvec r, const polz *a, size_t off, ssize_t stride, size_t len);
void polz_frompolx(polz r, const polx a);
void polzvec_frompolxvec(polz *r, const polxvec a, size_t off, ssize_t stride, size_t len);

void polz_add(polz r, const polz a, const polz b);
void polzvec_add(polz *r, const polz *a, const polz *b, size_t len);
void polz_sub(polz r, const polz a, const polz b);
void polzvec_sub(polz *r, const polz *a, const polz *b, size_t len);
void polz_slli(polz r, const polz a, int s);
void polzvec_slli(polz *r, const polz *a, size_t len, int s);
void polz_mul(polz r, const polz a, const polz b);
void polz_poly_mul(polz r, const polz a, const poly b);

void polz_split(poly lo, polz hi, const polz a, size_t d);
void polzvec_split(poly *lo, polz *hi, const polz *a, ssize_t stride, size_t len, size_t d);
void polz_bindec(poly *r, const polz a, ssize_t stride, size_t t);
void polzvec_bindec(poly *r, const polz *a, size_t len, ssize_t stride, size_t t);
void polz_bindec_topolxvec(polxvec r, const polz a, ssize_t stride, size_t t);
void polzvec_bindec_topolxvec(polxvec r, const polz *a, size_t len, ssize_t stride, size_t t);
void polz_decompose(poly *r, const polz a, ssize_t stride, size_t t, size_t d);
void polzvec_decompose(poly *r, const polz *a, size_t len, ssize_t stride, size_t t, size_t d);
void polz_decompose_topolxvec(polxvec r, const polz a, ssize_t stride, size_t t, size_t d);
void polzvec_decompose_topolxvec(polxvec r, const polz *a, size_t len, ssize_t stride, size_t t, size_t d);
void polz_reconstruct(polz r, const poly *a, ssize_t stride, size_t t, size_t d);
void polzvec_reconstruct(polz *r, const poly *a, size_t len, ssize_t stride, size_t t, size_t d);

void polz_sigmam1(polz r, const polz a);
void polzvec_sigmam1(polz *r, const polz *a, size_t len);
void polz_rotate(polz r, const polz a, size_t k);
void polzvec_rotate(polz *r, const polz *a, size_t len, size_t k);

void polzvec_gaussian(polz *r, size_t len, unsigned int log2sd, const uint8_t seed[SEEDLEN], uint64_t nonce);
int quil_polzvec_gaussian_private(polz *r, size_t len, unsigned int log2sd, const uint8_t seed[32], uint64_t nonce);
int64_t polzvec_sprodz(const polz *a, const polz *b, size_t len);

#endif
