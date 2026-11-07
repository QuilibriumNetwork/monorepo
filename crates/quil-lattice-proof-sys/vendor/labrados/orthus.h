#ifndef ORTHUS_H
#define ORTHUS_H

#include "proofsystem.h"

typedef struct _ort_block{
  poly **s;
} ort_block[1];

typedef struct _ort_witness{
  size_t nblock;      // number of blocks
  size_t nvec;        // number of vectors per block
  size_t n;           // length of vectors
  ort_block *block;   // array of blocks (nblock)
} ort_witness[1];

typedef struct _ort_cnstset{
  size_t nsparse;       // number of constraints
  sparsecnst *sparse;   // array of constraints (nsparse)
} ort_cnstset[1];

typedef struct _ort_statement{
  size_t nblock;      // number of blocks
  size_t nvec;        // number of vectors per block
  size_t n;           // length of vectors
  uint64_t *normsq;   // l2 norm squared of each vector (nvec)
  normtype *normty;   // norm type to be proven for each vector (nvec)
  ort_cnstset cs;     // Rq constraints
  int *preprocess;    // whether to preprocess each vector (nvec)
  uint8_t h[HASHLEN];
} ort_statement[1];

typedef struct _ort_proof{
  polz *m[7];
} ort_proof[1];

typedef struct _ort_params{
  size_t nblock;  // number of blocks
  size_t nvi;     // number of input vectors per block
  size_t nvpre;   // number of preprocessed vectors per block
  size_t nvt;     // total number of vectors per block
  size_t n;       // length of the vectors
  size_t r;       // number of rows of blocks
  size_t m;       // number of columns of blocks

  int *isexact;       // whether each vector needs an exact l2-norm (nvt)
  int *isbin;         // whether each vector needs a binary proof (nvt)
  size_t nexact;      // number of vectors to prove exact l2-norm
  size_t nbin;        // number of vectors to prove binary
  size_t nvdiff;      // number of vectors storing norm differences
  size_t nvlift;      // number of vectors storing lifts for l2-norm proofs
  size_t *idx_diff;   // idx in [nvt] of the norm difference for l2-norm proof (nvt)
  size_t *off_diff;   // offset in [n] of the norm difference (nvt)
  size_t *idx_sigma;  // idx in [nvt] of the sigmam1 of each vector (nvt)
  size_t *idx_lift;   // idx in [nvt] of the lift for l2-norm / binary proof for each vector (nvt)
  size_t *off_lift;   // offset in [n] of the lift (nvt)

  int *isproj;            // whether to project each vector (nvt)
  size_t nproj;           // number of projected vectors per block
  size_t *proj_nblocks;   // number of blocks projected together per vector (nvt), assumed to be pp->m for norm differences
  size_t *proj_nbits;     // number of bits of projections per vector (nvt)

  size_t base_unif;       // log2 of base to decompose uniform elements
  size_t base_lift_l2;    // log2 of base to decompose the lifts for exact l2-norms
  size_t base_lift_bin;   // log2 of base to decompose the lifts for binary proofs
  size_t base_quadg;      // log2 of base to decompose the quadratic garbage
  size_t base_zcol;       // log2 of base to decompose the amortization of columns
  size_t digits_unif;     // number of parts when decomposing in base 2**base_unif
  size_t digits_lift_l2;  // number of parts when decomposing in base 2**base_lift_l2
  size_t digits_lift_bin; // number of parts when decomposing in base 2**base_lift_bin
  size_t digits_quadg;    // number of parts when decomposing in base 2**base_quadg
  size_t randlen;         // length of the randomness for the outer commitments
  size_t kappa_inner;     // rank of the inner commitments
  size_t kappa_inner_pre; // rank of the preprocessed inner commitments
  size_t kappa_middle[7]; // rank of the middle commitments [preprocessed, 1st, 2nd, ...]
  size_t kappa_outer;     // rank of the outer commitments

  size_t off_zcol;              // offset in witness of the amortization of columns
  size_t off_incom;             // offset in witness of the inner commitments
  size_t off_outcom;            // offset in witness of the outer commitments
  size_t off_incom_pre;         // offset in witness of the preprocessed inner commitments
  size_t off_quadg;             // offset in witness of the quadratic garbage
  size_t off_liftings;          // offset in witness of the liftings
  size_t off_ling;              // offset in witness of the linear garbage
  size_t off_nttg;              // offset in witness of the ntt garbage
  size_t off_zrow_minus;        // offset in witness of the amortization of rows with negative powers
  size_t off_zrow_plus;         // offset in witness of the amortization of rows with positive powers
  size_t off_zrow_plus_alpha;   // offset in witness of alpha times zrow_plus
  size_t *off_proj;             // offset in witness of the projections (nvt)
  size_t off_middlecom[7];      // offset in witness of the middle commitments [preprocessed, 1st, 2nd, ...]
  size_t off_rand[7];           // offset in witness of the randomness for the outer commitments

  size_t len_zcol;              // length in witness of the amortization of columns
  size_t len_incom;             // length in witness of the inner commitments
  size_t len_outcom;            // length in witness of the outer commitments
  size_t len_incom_pre;         // length in witness of the preprocessed inner commitments
  size_t len_quadg;             // length in witness of the quadratic garbage
  size_t len_liftings;          // length in witness of the liftings
  size_t len_ling;              // length in witness of the linear garbage
  size_t len_nttg;              // length in witness of the ntt garbage
  size_t len_zrow_minus;        // length in witness of the amortization of rows with negative powers
  size_t len_zrow_plus;         // length in witness of the amortization of rows with positive powers
  size_t len_zrow_plus_alpha;   // length in witness of alpha times zrow_plus
  size_t *len_proj;             // length in witness of the projections (nvt)
  size_t len_proj_total;        // length in witness of the concatenation of projections
  size_t len_middlecom[7];      // length in witness of the middle commitments [preprocessed, 1st, 2nd, ...]
  size_t len_rand[7];           // length in witness of the randomness for the outer commitments

  size_t owt_parts;                 // number of parts in output witness
  size_t owt_idx_zcol;              // index in [owt_parts] of the amortization of columns
  size_t owt_idx_incom;             // index in [owt_parts] of the inner and outer commitments
  size_t owt_idx_incom_pre;         // index in [owt_parts] of preprocessed inner commitments
  size_t owt_idx_quadg;             // index in [owt_parts] of the quadratic garbage
  size_t owt_idx_liftings;          // index in [owt_parts] of the liftings
  size_t owt_idx_ling;              // index in [owt_parts] of the linear garbage
  size_t owt_idx_nttg;              // index in [owt_parts] of the ntt garbage
  size_t owt_idx_zrow_minus;        // index in [owt_parts] of zrow_minus
  size_t owt_idx_zrow_plus;         // index in [owt_parts] of zrow_plus
  size_t owt_idx_zrow_plus_alpha;   // index in [owt_parts] of zrow_plus_alpha
  size_t owt_idx_bin;               // index in [owt_parts] of the binary polynomials
  uint64_t *owt_normsq;             // normsq of output witness vectors (owt_parts)
} ort_params[1];

int ort_params_gen(ort_params pp, size_t *pibits, size_t *owtbits, 
                    const ort_statement st, int zk);
void ort_params_free(ort_params pp);
void ort_params_print(const ort_params pp);
void ort_params_print_debug(const ort_params pp);

void ort_witness_init(ort_witness wt, size_t nblock, size_t nvec, size_t n);
void ort_witness_free(ort_witness wt);

void ort_cnstset_init(ort_cnstset cs, size_t ncnst);
void ort_cnstset_free(ort_cnstset cs);
int ort_cnstset_check(const ort_cnstset cs, polxvec **sxq, polxvec *sxl, 
                      size_t nblock);

void ort_statement_init(ort_statement st, size_t nblock, size_t nvec, size_t n);
void ort_statement_free(ort_statement st);

int ort_verify(const ort_statement st, const ort_witness wt);

void ort_proof_init(ort_proof pi, const ort_params pp);
void ort_proof_free(ort_proof pi);
void ort_statement_new_init(statement ost, const ort_statement ist,
                            const ort_params pp);
void ort_witness_new_init(witness wt, const statement st); 
void ort_comkey_init(const ort_params pp);

void ort_preprocess(polz **outcom_ptr, poly **midcom_ptr, poly **incom_ptr,
                    const ort_statement st, const ort_block *block, 
                    const ort_params pp);
void ort_prove(ort_proof pi, statement ost, witness owt, const polz *outcom, 
               const poly *midcom, const poly *incom, const ort_statement ist, 
               const ort_witness iwt, const ort_params pp);
void ort_reduce(statement ost, const polz *outcom, const ort_statement ist,
                const ort_proof pi, const ort_params pp);

#endif