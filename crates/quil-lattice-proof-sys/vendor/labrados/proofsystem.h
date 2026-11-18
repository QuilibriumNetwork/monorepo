#ifndef PROOFSYSTEM_H
#define PROOFSYSTEM_H

#include <stdint.h>
#include <stddef.h>
#include <math.h>
#include "constraints.h"
#include "poly.h"
#include "polx.h"
#include "polz.h"

#define PS_Q ((1ULL<<LOGQ)-QOFF)
#define PS_TAU  sqrt(TAU1 + 4*TAU2) // bound on the l2-norm of the challenges
#define PS_T T // bound on the operator norm of the challenges
#define PS_CHALBITS 128 // bits per challenge seed

// if norm_l2(s) < b, then w.h.p. norm_inf(proj(s)) < 9.75 * b
#define JL_INF_MULT 9.75
// if norm_inf(proj(s)) > 9.75 * b, then w.h.p. norm_l2(s) > (9.75/0.74) * b
#define JL_INF_SLACK (JL_INF_MULT/0.74)
// need JL_INF_SLACK * b < PS_Q / 91 to apply JL
// need the coefs of proj(s) to be in 32 bits, so (9.75 * b) in 31 bits
#define JL_INF_MAXNORM MIN(PS_Q / (91.0 * JL_INF_SLACK), (1ULL<<31)/JL_INF_MULT)

// if norm_l2(s) < b, then w.h.p. norm_l2(proj(s)) < sqrt(337) * b
#define JL_L2_MULT 337
// if norm_l2(proj(s)) > sqrt(337) * b, then w.h.p norm_l2(s) > sqrt(337/30) * b
#define JL_L2_SLACK sqrt(JL_L2_MULT/30.0)
// need JL_L2_SLACK * b < PS_Q / 125 to apply JL
// need the coefs of proj(s) to be in 32 bits, so (9.75 * b) in 31 bits
#define JL_L2_MAXNORM MIN(PS_Q/(125.0*JL_L2_SLACK), (1ULL<<31)/JL_INF_MULT)

// need 2 * N * PS_MAXBINLEN * JL_INF_SLACK**2 < q
#define PS_MAXBINLEN PS_Q/(2*N*JL_INF_SLACK*JL_INF_SLACK)

// number of coefficients needed for the hardness of SIS with inf norm 1
#define SIS1_NCOEF 32

#define LOGEDIV2 2.05 // log(2*pi*e)/2
#define WIDTHMOD(b) ((((__uint128_t) 1) << (2*b))/12.0)

typedef enum {L2EXACT, L2APPROX, BIN, NONORM} normtype;

typedef struct _statement{
  size_t r;               // number of witness vectors
  size_t *n;              // length of each witness vector (r)
  uint64_t *normsq;       // squared l2-norm bound for each witness vector (r)
  uint64_t *normsq_req;   // squared l2-norm bounds that the proof is required to guarantee, ignored if == 0 (r)
  normtype *normty;       // norm type to be proven for each witness vector (r)
  rqcnstset rqcnst;       // constraints over the full ring Rq
  zqcnstset zqcnst;       // constraints over Zq, i.e., constant term = 0
  uint8_t h[HASHLEN];          // hash
#ifndef NDEBUG
  size_t maxr;
#endif
} statement[1];

typedef struct _witness{
  size_t r;       // number of witness vectors
  size_t *n;      // length of each witness vector (r)
  poly **s;       // concatenation of witness vectors (\sum_i n[i])
#ifndef NDEBUG
  size_t maxr;
#endif
} witness[1];

void statement_init(statement st, size_t r, size_t maxr);
void statement_free(statement st);

void witness_init(witness wt, size_t r, size_t maxr);
void witness_copy(witness out, const witness in);
void witness_free(witness wt);

int sis_secure(size_t rank, double norm);
void update_hash_polz(uint8_t h[HASHLEN], const polz *in, size_t len);
void commit(polxvec out, const polxvec in);
size_t commit_add(polxvec out, const polxvec in, size_t off_comkey);

void jl_sample_mat(uint8_t **jlmat1, uint8_t **jlmat2, uint8_t h[HASHLEN], size_t len);
void jl_project(int32_t p[256], const poly *s, size_t len, const uint8_t *jlmat1,
                const uint8_t *jlmat2);
void jl_aggregate_mat(polxvec phi, const uint8_t *jlmat1, const uint8_t *jlmat2, 
                      const int64_t chalz[256]);
void jl_aggregate_proj(polxvec phi, size_t nbits, const int64_t chalz[256]);

int verify(const statement st, const witness wt);

void randombits64(int64_t *buf, size_t nbits);
void sample_chalz(int64_t *chalz, size_t nchalz, uint8_t h[HASHLEN]);
void sample_chalx_aggregate(polxvec chalx, uint8_t h[HASHLEN]);
void sample_chalx_uniform(polxvec chalx, uint8_t h[HASHLEN]);
void sample_chalx_amortize(polx *chalx, size_t nchalx, uint8_t h[HASHLEN]);

void polxvec_powers(polxvec powers, int64_t base, int64_t v, int64_t v_top);
void outcom_clear(polz a);

void ps_addcheck_commit_in_clear(comcnst c, const polz *U, size_t rank, 
                                 size_t pos, size_t len);
void ps_addcheck_commit_middle(comcnst c, size_t rank, size_t cpos, size_t wpos,
                               size_t wlen);
void ps_addcheck_commit_outer(comcnst c, size_t cpos, size_t wpos, size_t wlen, 
                              size_t base_unif, size_t digits_unif);
void ps_addcheck_commit_coeffs(sparsecnst *c, polz outcom, size_t wpos, 
                               size_t base_unif, size_t digits_unif);
void ps_addcheck_lift_zero_coeff(sparsecnst c[LIFTS], size_t liftpos);

void compile_bincnst(statement st, witness wt);

#endif
