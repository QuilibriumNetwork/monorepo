#ifndef TEST_CONSTRAINTS_SETUP_H
#define TEST_CONSTRAINTS_SETUP_H

#include "polx.h"
#include "constraints.h"

void polxvec_sparse(polxvec v, size_t rank, int dist, const uint8_t seed[SEEDLEN], 
                    uint64_t *nonce);
void polx_array_sparse(polx *v, size_t len, int dist, const uint8_t seed[SEEDLEN], 
                       uint64_t *nonce);
void polxvec_setzero_except_ctcoeff(polxvec a, size_t j);
void full_quadfunc_eval_add(polxvec ev, const polxvec sx[], size_t r, 
                            polx a[r][r]);
void full_linfunc_eval_add(polxvec ev, const polxvec sxl, const polxvec phi);
void quadfunc_set(quadfunc quad, size_t r, const polx a[r][r]);
void linfunc_set(linfunc lin, const polxvec phi);

void sparsecnst_sample(sparsecnst out, size_t rank, int full, int isquad, 
                       int triangular, size_t r, const polxvec sxl, 
                       const polxvec sxq[], const uint8_t seed[SEEDLEN], 
                       uint64_t *nonce);

void full_comcnst_eval(polxvec ev, const polxvec sxl, const polxvec b, 
                       size_t ncom, size_t comk_off[ncom], 
                       size_t comw_off[ncom], size_t comw_len[ncom], 
                       int64_t scalar[ncom], const polxvec phi);
void comcnst_set(comcnst cnst, size_t comk_off[cnst->ncom], 
                 size_t comw_off[cnst->ncom], size_t comw_len[cnst->ncom], 
                 int64_t scalar[cnst->ncom], const polxvec phi,const polxvec b);
void comcnst_sample(comcnst cnst, size_t rank, const polxvec sxl, 
                    const uint8_t seed[SEEDLEN], uint64_t *nonce);

#endif