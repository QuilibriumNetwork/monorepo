#ifndef POLX_H
#define POLX_H

#include "data.h"
#include "poly.h"

struct polx_str {
  double width;
  poly proj[K];
};

struct polxvec_str {
  size_t alloc;
  size_t off;
  ssize_t stride;
  size_t len;
  double *widths;
  poly *proj[K];
};

typedef struct polx_str polx[1];
typedef struct polx_str *polx_ptr;
typedef struct polxvec_str polxvec[1];
typedef struct polxvec_str *polxvec_ptr;

void polxvec_init(polxvec r, size_t len, int widths);
void polxvec_init_subvec(polxvec r, const polxvec a, size_t off, ssize_t stride, size_t len);
void polxvec_init_subvec2(polxvec r, const polxvec a, size_t off, ssize_t stride, size_t len);
void polxvec_init_frompolx(polxvec r, polx a);
void polxvec_free(polxvec r);
void polxvec_setwidths1(polxvec r, size_t off, ssize_t stride, size_t len, double width);

void polx_print(const polx a);
void polxvec_print(const polxvec a, size_t off, ssize_t stride, size_t len);
void polx_getcoeff(zz r, const polx a, int k);
void polxvec_getcoeff(zz r, const polxvec a, size_t j, int k);

void polx_setzero(polx r);
void polxvec_setzero(polxvec r, size_t off, ssize_t stride, size_t len);
int polx_iszero(const polx a);
int polxvec_iszero(const polxvec a);
int polx_iszero_constcoeff(const polx a);
int polxvec_iszero_constcoeff(const polxvec a, size_t j);

void polx_copy(polx r, const polx a);
void polxvec_copy(polxvec r, const polxvec a);
void polx_monomial(polx r, int k, int64_t v);  // FIXME: swapped order of k,v
void polxvec_monomial(polxvec r, size_t j, int k, int64_t v);
void polx_fromint64vec(polx r, const int64_t *a, double width);
void polxvec_fromint64vec(polxvec r, const int64_t *a, size_t len, size_t deg, double width);
void polxvec_fromint64vec2(polxvec r, const int64_t *a, size_t len, size_t deg, double width);
void polx_frompoly(polx r, const poly a, double width);
void polxvec_frompolyvec(polxvec r, const poly *a, ssize_t stride, size_t len, double width);
void polx_frompolxvec(polx r, const polxvec a, size_t j);

void polx_almostuniform(polx r, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polxvec_almostuniform(polxvec r, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polx_ternary(polx r, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polxvec_ternary(polxvec r, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polx_quarternary(polx r, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polxvec_quarternary(polxvec r, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polx_challenge(polx r, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polxvec_challenge(polxvec r, const uint8_t seed[SEEDLEN], uint64_t nonce);

void polx_refresh(polx r);
void polxvec_refresh(polxvec r);
void polx_reduce(polx r);
void polxvec_reduce(polxvec r);

void polx_neg(polx r, const polx a);
void polxvec_neg(polxvec r, const polxvec a);
void polx_add(polx r, const polx a, const polx b);
void polxvec_add(polxvec r, const polxvec a, const polxvec b);
void polx_sub(polx r, const polx a, const polx b);
void polxvec_sub(polxvec r, const polxvec a, const polxvec b);

void polx_ntt(polx r, const polx a);
void polxvec_ntt(polxvec r, const polxvec a);
void polx_invntt(polx r, const polx a);
void polxvec_invntt(polxvec r, const polxvec a);
void polxvec_ntt_interleaved_half(polxvec r, const polxvec a);
void polxvec_invntt_interleaved(polxvec r, const polxvec a);

void polx_mul(polx r, const polx a, const polx b);
void polx_poly_mul(polx r, const polx a, const poly b, double width);
void polxvec_mul(polxvec r, const polxvec a, const polxvec b);
void polxvec_polx_mul(polxvec r, polx a, const polxvec b);
void polx_mul_add(polx r, const polx a, const polx b);
void polxvec_mul_add(polxvec r, const polxvec a, const polxvec b);
void polxvec_polx_mul_add(polxvec r, polx a, const polxvec b);
void polxvec_sprod(polxvec r, const polxvec a, const polxvec b);
void polxvec_sprod_add(polxvec r, const polxvec a, const polxvec b);
size_t polxvec_sprod_extension(polxvec c, const polxvec a, const polxvec b);
size_t polxvec_sprod_extension_add(polxvec c, const polxvec a, const polxvec b);
size_t polxvec_collaps_add_extension(polxvec c, const polxvec a, const polxvec b, size_t off_a);
size_t polxvec_pairwise_mul(polxvec h, const polxvec a);
size_t polxvec_pairwise_sprod(polxvec g, const polxvec a, const polxvec b, size_t r, size_t n);

void polx_scale(polx r, const polx a, int64_t s);
void polx_scale_frompoly(polx r, const poly a, double width, int64_t s);
void polxvec_scale(polxvec r, const polxvec a, int64_t s);
void polxvec_scale_frompolyvec(polxvec r, const poly *a, ssize_t stride, size_t len, double width, int64_t s);
void polx_scale_add(polx r, const polx a, int64_t s);
void polxvec_scale_add(polxvec r, const polxvec a, int64_t s);

void polx_bindec(poly *r, const polx a, ssize_t stride, size_t t);
void polxvec_bindec(poly *r, const polxvec a, ssize_t stride, size_t t);
void polx_decompose(poly *r, const polx a, ssize_t stride, size_t t, size_t d);
void polxvec_decompose(poly *r, const polxvec a, ssize_t stride, size_t t, size_t d);
void polx_reconstruct(polx r, const poly *a, ssize_t stride, size_t t, size_t d);
void polxvec_reconstruct(polxvec r, const poly *a, ssize_t stride, size_t t, size_t d);

void polx_sigmam1(polx r, const polx a);
void polxvec_sigmam1(polxvec r, const polxvec a);
void polx_sigma5(polx r, const polx a);
void polxvec_sigma5(polxvec r, const polxvec a);
void polx_sigma5inv(polx r, const polx a);
void polxvec_sigma5inv(polxvec r, const polxvec a);

void polx_flip(polx r, const polx a);
void polxvec_flip(polxvec r, const polxvec a);

#endif
