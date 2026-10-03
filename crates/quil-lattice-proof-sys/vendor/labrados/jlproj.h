#ifndef JLPROJ_H
#define JLPROJ_H

#include <stdint.h>
#include "data.h"
#include "poly.h"
#include "polz.h"

// projection coefficients have stddev sqrt(normsq); must stay below 2^31; hence bound of 2^31/8 = 2^28
#define JLMAXNORM MIN((((uint64_t)1 << LOGQ) - QOFF)/125,(uint64_t)1 << 28)
#define JLMAXNORMSQ (JLMAXNORM*JLMAXNORM)

void poly_jlproj_add(int32_t r[256], const poly p, const uint8_t mat[256*N/8]);
void polyvec_jlproj_add(int32_t r[256], const poly *p, size_t len, const uint8_t *mat);
void polxvec_jlproj_collapsmat(polxvec r, const uint8_t *mat, const int64_t alpha[256]);
int64_t jlproj_collapsproj(const int32_t p[256], const int64_t alpha[256]);
uint64_t jlproj_normsq(const int32_t p[256]);

void polyvec_jlproj_add_bin1(int32_t r[256], const poly *p, size_t len, const uint8_t *mat1, const uint8_t *mat2);

void jlproj_expand_challenge(int64_t alpha[256], const uint8_t buf[256*QBYTES]);

#endif
