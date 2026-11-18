#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include <immintrin.h>
#include <complex.h>
#include "data.h"

typedef union vecn poly[1];
typedef union vecn *poly_ptr;

__attribute__((const))
uint64_t next2power(uint64_t a);
__attribute__((const))
size_t extlen(size_t len, size_t deg);
__attribute__((const))
int16_t modp(int64_t a, const pdata prime);
__attribute__((const))
int16_t pow_simple(int16_t a, int e, const pdata prime);
void poly_setzero(poly r);
void polyvec_setzero(poly *r, ssize_t stride, size_t len);
int polyvec_isbinary(const poly *r, ssize_t stride, size_t len);
void polyvec_fromint64vec(poly *r, const int64_t *a, ssize_t stride, size_t len, size_t deg, const pdata prime);
void polyvec_copy(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len);
void poly_binary_fromuint64(poly r, uint64_t a);
void poly_monomial_ntt(poly r, int16_t v, int k, const pdata prime);

void polyvec_uniform(poly *r, size_t len, const pdata prime, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polyvec_ternary(poly *r, ssize_t stride, size_t len, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polyvec_quarternary(poly *r, ssize_t stride, size_t len, const uint8_t seed[SEEDLEN], uint64_t nonce);
void polyvec_gaussian(poly *r, size_t len, unsigned int log2sd,
                      const uint8_t seed[SEEDLEN], uint64_t nonce);
void polyvec_challenge(poly *c, ssize_t stride, size_t len, const uint8_t seed[SEEDLEN], uint64_t nonce);

int64_t polyvec_sprodz_ref(const poly *a, const poly *b, ssize_t stride_a, ssize_t stride_b, size_t len);
int64_t polyvec_sprodz(const poly *a, const poly *b, ssize_t stride_a, ssize_t stride_b, size_t len);
double polyvec_norm(const poly *a, ssize_t stride, size_t len);

void poly_reduce(poly r, const pdata prime);
void polyvec_reduce(poly *r, ssize_t stride, size_t len, const pdata prime);
void poly_center(poly r, const pdata prime);
void polyvec_center(poly *r, ssize_t stride, size_t len, const pdata prime);
void poly_csubp(poly r, const pdata prime);
void polyvec_csubp(poly *r, ssize_t stride, size_t len, const pdata prime);
void poly_caddp(poly r, const pdata prime);
void polyvec_caddp(poly *r, ssize_t stride, size_t len, const pdata prime);
void poly_quot_add(poly r, const poly a, const pdata prime);
void polyvec_quot_add(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime);

void poly_neg(poly r, const poly a);
void polyvec_neg(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len);
void poly_add(poly r, const poly a, const poly b);
void polyvec_add(poly *r, const poly *a, const poly *b, ssize_t stride_r, ssize_t stride_a, ssize_t stride_b, size_t len);
void poly_sub(poly r, const poly a, const poly b);
void polyvec_sub(poly *r, const poly *a, const poly *b, ssize_t stride_r, ssize_t stride_a, ssize_t stride_b, size_t len);

void poly_ntt_ref(poly r, const poly a, const pdata prime);
void poly_invntt_ref(poly r, const poly a, const pdata prime);
void poly_ntt(poly r, const poly a, const pdata prime);
void polyvec_ntt(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime);
void poly_invntt(poly r, const poly a, const pdata prime);
void polyvec_invntt(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime);
void poly_nttunpack(poly r, const pdata prime);
void polyvec_ntt_interleaved(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime);
void polyvec_ntt_interleaved_half(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime);
void polyvec_invntt_interleaved(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime);

void poly_pointwise(poly r, const poly a, const poly b, const pdata prime);
void polyvec_pointwise(poly *r, const poly *a, const poly *b, ssize_t stride_r, ssize_t stride_a, ssize_t stride_b, size_t len, const pdata prime);
void polyvec_poly_pointwise(poly *r, const poly a, const poly *b, ssize_t stride_r, ssize_t stride_b, size_t len, const pdata prime);
void poly_pointwise_add(poly r, const poly a, const poly b, const pdata prime);
void polyvec_pointwise_add(poly *r, const poly *a, const poly *b, ssize_t stride_r, ssize_t stride_a, ssize_t stride_b, size_t len, const pdata prime);
void polyvec_poly_pointwise_add(poly *r, const poly a, const poly *b, ssize_t stride_r, ssize_t stride_b, size_t len, const pdata prime);
void polyvec_sprod_pointwise(poly r, const poly *a, const poly *b, ssize_t stride_a, ssize_t stride_b, size_t len, const pdata prime);
void polyvec_sprod_pointwise_add(poly r, const poly *a, const poly *b, ssize_t stride_a, ssize_t stride_b, size_t len, const pdata prime);

void polyvec_sprod_extension(poly *c, const poly *a, const poly *b, ssize_t stride_c, ssize_t stride_a, ssize_t stride_b, size_t deg, size_t clen, size_t blen, const pdata prime);
void polyvec_collaps_add_extension(poly *c, const poly *b, const poly *a, ssize_t stride_c, ssize_t stride_b, ssize_t stride_a, size_t deg, size_t clen, size_t blen, const pdata prime);
__attribute__((const))
size_t pwidx(size_t i, size_t j, size_t r);
void polyvec_pairwise_sprod(poly *g, const poly *a, const poly *b, size_t r, size_t n, const pdata prime);
void polyvec_pairwise_pointwise(poly *g, const poly *a, const poly *b, ssize_t stride_g, ssize_t stride_a, ssize_t stride_b, size_t r, size_t s, const pdata prime);

void poly_scale(poly r, const poly a, int16_t s, const pdata prime);
void polyvec_scale(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, int16_t s, const pdata prime);
void poly_scale_add(poly r, const poly a, int16_t s, const pdata prime);
void polyvec_scale_add(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, int16_t s, const pdata prime);

void poly_mul(poly r, const poly a, const poly b, const pdata prime);

void poly_fft(double complex r[N/2], const poly a);
void poly_invfft(poly r, double complex a[N/2]);
double poly_opnorm(const poly a);

void poly_sigmam1(poly r, const poly a);
void polyvec_sigmam1(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len);
void poly_sigmam1_ntt(poly r, const poly a);
void polyvec_sigmam1_ntt(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len);
void poly_sigma(poly r, const poly a, int k);
void poly_sigma5(poly r, const poly a);
void polyvec_sigma5(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len);
void poly_sigma5inv(poly r, const poly a);
void polyvec_sigma5inv(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len);
void poly_flip(poly r, const poly a);
void polyvec_flip(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len);
void poly_flip_ntt(poly r, const poly a, const pdata prime);
void polyvec_flip_ntt(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t len, const pdata prime);

void poly_print(const poly a);
void polyvec_print(const poly *a, ssize_t stride, size_t len);

void poly_rotate(poly r, const poly a, size_t k);
void polyvec_cfft(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t d, size_t k);
void polyvec_cinvfft(poly *r, const poly *a, ssize_t stride_r, ssize_t stride_a, size_t d, size_t k);

#endif
