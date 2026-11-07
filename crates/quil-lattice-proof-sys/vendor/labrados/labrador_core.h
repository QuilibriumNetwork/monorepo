#ifndef LABRADOR_CORE_H
#define LABRADOR_CORE_H

#include <stdint.h>
#include <stddef.h>
#include "proofsystem.h"
#include "poly.h"
#include "polx.h"
#include "polz.h"

typedef enum {LAB_Z, LAB_INCOM, LAB_QUADG, LAB_LING, LAB_U1, LAB_RAND1,
              LAB_PROJ, LAB_RAND2, LAB_LIFT, LAB_RAND3, LAB_U2, LAB_RAND4, 
              LAB_BIN, LAB_OUTCOM} lab_parts;

typedef struct _lab_proof{
  polz *m[4];      // prover's messages
  int32_t p[256];  // 2nd prover's message if projections are sent in the clear
} lab_proof[1];

typedef struct _lab_params{
  size_t r_old;            // number of witness vectors before split
  size_t *rr;              // number of parts to split original witness vectors
  size_t r;                // number of witness vectors after split, r = sum(rr)
  size_t *n;               // length of each witness vector after split (r)
  size_t nn;               // length of witness, i.e., nn = \sum_i n[i]
  size_t nmax;             // max length of a witness vector after split
  size_t kappa[3];         // commitment ranks (inner, middle and outer)
  size_t randlen;          // randomness rank for the outer commitments
  size_t bz;               // log2 of base to decompose the amortized openning z
  size_t bu;               // log2 of base to decompose uniform elements
  size_t bg;               // log2 of base to decompose the inner products gij
  size_t fz;               // number of parts when decomposing in base 2**bz
  size_t fu;               // number of parts when decomposing in base 2**bu
  size_t fg;               // number of parts when decomposing in base 2**bg
  uint64_t *normsq;        // normsq of witness vectors after split (r)
  uint64_t normsq_global;  // global norm of witness vectors
  uint64_t normsq_new[4];  // bounds for new witness parts
  size_t off[14];          // offsets in new witness / proof indexed by labparts
  size_t len[14];          // lengths in new witness / proof indexed by labparts
  int compressed;          // whether all prover's messages are compressed
  int tail;                // whether all prover's messages are sent in clear
} lab_params[1];

void lab_proof_init(lab_proof pi, const lab_params pp);
void lab_proof_free(lab_proof pi);

int lab_params_gen(lab_params outpp, size_t *pibits, size_t *owtbits, 
                   const statement st, int compressed, int tail, int zk, 
                   int split, int global_norm_check, double slack_norm_check);
void lab_params_print(const lab_params pp);
void lab_params_free(lab_params pp);

void lab_witness_init(witness owt, const lab_params pp);
void lab_statement_init(statement ost, const statement ist, const lab_params pp);
void lab_comkey_init(const lab_params pp);

void lab_quadg(poly *gy, polz *gz, const polxvec sx[], size_t r, size_t fg, 
           size_t bg, int tail);
void lab_ling(poly *hy, const polxvec sx[], const polxvec phi[], size_t r, 
          size_t fu, size_t bu);

void lab_addcheck_amortization(comcnst c, size_t kappa_inner, size_t r, 
                               size_t nmax, size_t n, size_t t_off, size_t fz, 
                               size_t bz, size_t fu, size_t bu, polx chalx[r]);
void lab_addcheck_quadg(sparsecnst c, size_t r, size_t g_off, size_t fz, 
                        size_t bz, size_t fg, size_t bg, polx chalx[r]);
void lab_addcheck_ling(sparsecnst c, size_t r, size_t n, size_t z_off, 
                       size_t h_off, size_t fz, size_t bz, size_t fu, size_t bu, 
                       polx chalx[r], const polxvec phi[r]);                     

int compare_decreasing(const void *a, const void *b);
size_t trimat_idx(size_t i, size_t j, size_t len);

#endif