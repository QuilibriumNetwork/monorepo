#ifndef DACHSHUND_H
#define DACHSHUND_H

#include <stdint.h>
#include "poly.h"
#include "polx.h"
#include "polz.h"
#include "proofsystem.h"
#include "pack.h"

#define DCH_MAXPARTS 150
#define DCH_MAXLEN 50000
#define DCH_MAXNORMSQ PS_Q/(JL_INF_SLACK*JL_INF_SLACK+3)

typedef struct _dch_proof{
  polz *com;
} dch_proof[1];

typedef struct _dch_params{
  size_t r;           // new number of parts
  size_t *n;          // lengths of new parts (r)
  uint64_t *normsq;   // new squared l2-norm bounds (r)
  normtype *normty;   // new norm types to be proven (r)

  size_t nexact;            // number of original exact vectors
  size_t nexact_merge;      // number of exact vectors after merge
  size_t nbin_merge;        // number of binary vectors after merge
  size_t napprox_merge;     // number of approx vectors after merge
  size_t *exact_map;        // mapping from [nexact_merge] to [nexact] (nexact_merge)

  size_t nquad;             // number of quadratic constraints
  size_t quad_sumranks;     // sum of the ranks of all the quadratics
  size_t quad_nterms;       // number of quadratic terms accross all quadratic constraints
  size_t quad_maxrank;      // maximum rank of all the quadratics

  size_t base_unif;         // log2 of base to decompose uniform elements
  size_t base_liftings;     // log2 of base to decompose liftings
  size_t base_quad_left;    // log2 of base to decompose quad_left
  size_t digits_unif;       // number of parts when decomposing in base 2**base_unif
  size_t digits_liftings;   // number of parts when decomposing in base 2**base_liftings
  size_t digits_quad_left;  // number of parts when decomposing in base 2**base_quad_left

  size_t nincom;            // number of inner commitments
  size_t *incom_offw;       // offset in [witness|liftings|diff] of the data committed in the inner commitments (nincom)
  size_t *incom_lenw;       // length of the witness for the inner commitments (nincom)
  size_t *kappa_inner;      // rank of inner commitments (nincom)
  size_t kappa_middle;      // rank of middle commitment
  size_t kappa_outer;       // rank of outer commitment
  size_t randlen;           // length of the randomness for the outer commitment

  size_t *off_exact;        // offset in witness of the exact vectors (nexact) 
  size_t off_liftings;      // offset in witness of the liftings
  size_t off_diff;          // offset in witness of the norm differences
  size_t *off_sigma;        // offset in witness of the sigmam1 of the exact vectors (nexact)
  size_t *off_incom;        // offset in witness of the inner commitments (nincom)
  size_t off_midcom;        // offset in witness of the middle commitment
  size_t off_rand;          // offset in witness of the binary randomness for the outer
  size_t off_quad_left;     // offset in witness of the left part for the quadratics
  size_t off_quad_right;    // offset in witness of the right part for the quadratics 

  size_t *len_exact_merge;  // length of each merged exact vector (nexact_merge)
  size_t len_exact_total;   // length of all the exact vectors
  size_t len_bin_total;     // length of all the binary vectors
  size_t len_com_inner;     // length of all the inner commitments
  size_t len_quad;          // length of all the vectors in the left (or right) part for the quadratics

  size_t *idx_exact;          // index in input witness of the exact vectors (nexact)
  size_t *idx_exact_merge;    // index in output witness of the merged exact vectors (nexact_merge)
  size_t *idx_sigma;          // index in output witness of the sigmam1 of the merged exact vectors (nexact_merge)
  size_t idx_quad;            // index in output witness of the first quad vector
  size_t *nparts_exact_merge; // number of parts that each merged exact vector takes in the new witness (nexact_merge)
  size_t nparts_quad;         // number of parts that each quad vector takes in new witness (same for all vectors)
} dch_params[1];

int dch_params_gen(dch_params pp, size_t *pibits, size_t *owtbits,
                   const statement st, int zk);
void dch_params_print(const dch_params pp);
void dch_params_free(dch_params pp);
void dch_proof_free(dch_proof pi);
void dch_prove(dch_proof pi, statement ost, witness owt, const statement ist,
               const witness iwt, const dch_params pp);
void dch_reduce(statement ost, const statement ist, const dch_proof pi,
                const dch_params pp);

// Dachshund + Pack

typedef struct _dch_pack_proof{
  dch_proof pi_dch;
  pack_proof pi_pack;
} dch_pack_proof[1];

typedef struct _dch_pack_params{
  dch_params pp_dch;
  pack_params pp_pack;
} dch_pack_params[1];

void dch_pack_proof_free(dch_pack_proof pi);

int dch_pack_params_gen(dch_pack_params pp, size_t *pibits, const statement st, 
                        int zk);
void dch_pack_params_print(const dch_pack_params pp);
void dch_pack_params_free(dch_pack_params pp);

/* Returns 0 on success; nonzero aborts proving without a usable proof. */
int dch_pack_prove(dch_pack_proof pi, const statement ist, 
                    const witness iwt, const dch_pack_params pp);
int dch_pack_verify(const statement ist, const dch_pack_params pp, 
                    const dch_pack_proof pi);

#endif
