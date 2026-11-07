#ifndef CONSTRAINTS_H
#define CONSTRAINTS_H

#include <stddef.h>
#include "polx.h"

/* 
  quadfunc represents a quadratic function 
  quadfunc(s) = \sum_ij a[i][j]*<s[i],s[j]>, where the matrix a is stored 
  in a sparse way.
    - len: number of non-zero entries of a.
    - rows: rows[i] is the index of the row for the i-th non-zero entry of a.
    - cols: cols[i] is the index of the column for the i-th non-zero entry of a.
    - coeffs: coeffs[i] is the value of the i-th non-zero entry of a.
  Therefore, quadfunc(s) = \sum_i coeffs[i]*<s[rows[i]],s[cols[i]]>.
*/
typedef struct _quadfunc{
  size_t len;
  size_t *rows;
  size_t *cols;
  polx *coeffs;
} quadfunc[1];

/*
  linfunc represents a linear function linfunc(s) = <phi, s>, where the 
  vector phi is stored in a sparse way.
    - rank: number of linear functions contained in parallel. It's a power of 2.
    - nparts: number of parts in which phi is split.
  The i-th part corresponds to the expression <phi[i], s[off[i]]>, where the
  length of the vectors is given by phi[i]->len. If rank is greater than 1, the
  inner product takes place over the corresponding extension ring.
*/
typedef struct _linfunc{
  size_t rank;
  size_t nparts;
  size_t *off;
  polxvec *phi;
} linfunc[1];

/*
  sparsecnst represents a constraint of the form: quadfunc(s) + linfunc(s) = b.

  It must be that b->len == lin->rank.
*/
typedef struct _sparsecnst{
  quadfunc quad;
  linfunc lin;
  polxvec b;
} sparsecnst[1];

/*
  comcnst represents a commitment contraint of the form
  <comkey, s> + <phi, s> = b, where the multiplication by comkey happens over
  the extension ring given by the rank, and the multiplication by phi is of the
  form polx times polxvec, i.e., each polynomial in phi multiplies rank
  polynomials in s.

  There are ncom terms representing multiplication by comkey.
  - comk_off[i]: offset of comkey.
  - comw_off[i]: offset of the witness that gets multiplied by comkey.
  - comw_len[i]: length of the witness that gets multiplied by comkey.
  - scalar[i]: scalar that multiplies the term.
  Therefore, this part is of the form: 
  \sum_i scalar[i] * <comkey[comk_off[i]], s[comw_off[i]]>.

  There vector phi is stored in a sparse way using nphi parts.
  - phiw_off[i]: offset of the witness that gets multiplied by phi.
  - phi[i]: each polx in phi[i] multiplies rank polynomials in the witness.
*/
typedef struct _comcnst{
  size_t rank;
  polxvec b;

  size_t ncom;
  size_t *comk_off;
  size_t *comw_off;
  size_t *comw_len;
  int64_t *scalar;

  size_t nphi;
  size_t *phiw_off;
  polxvec *phi;
} comcnst[1];

/*
  sigmam1cnst represents a constraint of the form: c*sigmam1(s1) = s2, where
  s1 is at offset off1 and has length len, and s2 is at offset off2 and has
  length len. If mul==0 then c is assumed to be 1; otherwise c is initialized
  to the appropiate value.
*/
typedef struct _sigmam1cnst{
  size_t off1;
  size_t off2;
  size_t len;
  int mul;
  polxvec c;
} sigmam1cnst[1];

/*
  intcnst represents a constraint indicating that the polynomial at offset off
  and with rank*N coefficients is an integer, i.e., every coefficient other than
  the constant one is zero.
*/
typedef struct _intcnst{
  size_t off;
  size_t rank;
} intcnst[1];

/*
  rqcnst represents a set of constraints that hold over the full ring Rq
    - nsparse: number of sparsecnst.
    - sparse_nchal: number of challenges needed to aggregate the sparsecnst.
    - sparse: array of sparsecnst.
    - ncom: number of comcnst.
    - com_nchal: number of challenges needed to aggregate the comcnst.
    - com: array of comcnst.
*/
typedef struct _rqcnstset {
  size_t nsparse;
  size_t sparse_nchal;
  sparsecnst *sparse;

  size_t ncom;
  size_t com_nchal;
  comcnst *com;
} rqcnstset[1];

/*
  zqcnst represents a set of constraints that hold over Zq, i.e., when looking
  at the constant coefficient of the polynomials. Note that each sigmam1cnst can 
  be expressed as N*len linear constraints over Zq, where len is the length of 
  the corresponding vectors.
    - nsparse: number of sparsecnst.
    - sparse_nchal: number of challenges needed to aggregate the sparsecnst.
    - sparse: array of sparsecnst. All the constraints have rank 1.
    - nsigmam1: number of sigmam1cnst.
    - sigmam1_nchal: number of challenges needed to aggregate the sigmam1cnst.
    - sigmam1: array of sigmam1cnst.
*/
typedef struct _zqcnstset {
  size_t nsparse;
  size_t sparse_nchal;
  sparsecnst *sparse;

  size_t nsigmam1;
  size_t sigmam1_nchal;
  sigmam1cnst *sigmam1;

  size_t nint;
  size_t int_nchal;
  intcnst *intc;

#ifndef NDEBUG
  size_t maxnsparse;
  size_t maxnsigmam1;
#endif
} zqcnstset[1];

void quadfunc_init(quadfunc quad, size_t len, size_t maxlen);
void quadfunc_free(quadfunc quad);
void quadfunc_eval_add(polxvec ev, const quadfunc quad, const polxvec sx[]);

void linfunc_init(linfunc lin, size_t rank, size_t nparts, size_t maxnparts);
void linfunc_free(linfunc lin); 
void linfunc_eval_add(polxvec ev, const linfunc lin, const polxvec sx); 

void sparsecnst_init(sparsecnst cnst, size_t rank);
void sparsecnst_copy(sparsecnst out, const sparsecnst in);
/* Borrow immutable public coefficient/RHS storage; own all index metadata.
 * The source MUST remain alive and unchanged until the destination is freed.
 * Consumers must not modify polynomial coefficients or width arrays. */
void sparsecnst_borrow_public(sparsecnst out, const sparsecnst in);
void sparsecnst_copy2(sparsecnst out, const sparsecnst in, size_t maxlen);
void sparsecnst_free(sparsecnst cnst);
void sparsecnst_refresh(sparsecnst cnst);
void sparsecnst_eval(polxvec ev, const sparsecnst cnst, const polxvec sxq[], 
                     const polxvec sxl);
int sparsecnst_check(const sparsecnst cnst, const polxvec sxq[], 
                     const polxvec sxl, int full);
void sparsecnst_aggregate_add(sparsecnst out, const sparsecnst *in, 
                              size_t ncnst, const polxvec chal, 
                              const int64_t *chalz, int full);

void comcnst_init(comcnst cnst, size_t rank, size_t ncom, size_t nphi, 
                  size_t maxnphi);
void comcnst_copy(comcnst out, const comcnst in);
void comcnst_free(comcnst cnst);
void comcnst_eval(polxvec ev, const comcnst cnst, const polxvec sx);
int comcnst_check(const comcnst cnst, const polxvec sx);
void comcnst_aggregate_add(sparsecnst out, const comcnst *in, size_t ncnst, 
                           const polxvec chal);

void sigmam1cnst_init(sigmam1cnst cnst, size_t off1, size_t off2, size_t len,
                      int mul);
void sigmam1cnst_copy(sigmam1cnst out, const sigmam1cnst in);
void sigmam1cnst_free(sigmam1cnst cnst);
int sigmam1cnst_check(const sigmam1cnst cnst, const polxvec sx);
void sigmam1cnst_aggregate_add(sparsecnst out, const sigmam1cnst *in, 
                               size_t ncnst, const polxvec chalx);

void intcnst_copy(intcnst out, const intcnst in);
int intcnst_check(const intcnst cnst, const polxvec sx);
void intcnst_aggregate_add(sparsecnst out, const intcnst *in, size_t ncnst,
                           const int64_t *chalz);

void rqcnstset_init(rqcnstset rqc, size_t nsparse, size_t ncommit);
void rqcnstset_free(rqcnstset rqc);
int rqcnstset_check(const rqcnstset rqc, const polxvec sxq[],const polxvec sxl);
void rqcnstset_aggregate_add(sparsecnst out, const rqcnstset rqc, 
                             const polxvec chal);

void zqcnstset_init(zqcnstset zqc, size_t nsparse, size_t maxnsparse, size_t nsigmam1, size_t nsigmam1max, size_t nint);
void zqcnstset_free(zqcnstset zqc);
int zqcnstset_check(const zqcnstset zqc, const polxvec sxq[],const polxvec sxl);
void zqcnstset_aggregate_add(sparsecnst out, const zqcnstset zqc, 
                             const int64_t *chalz, const polxvec chalx);

void polxvec_rotation_aggregate_add(polxvec r, const polxvec a, const polxvec b);                             

#define quil_zqcnstset_aggregate_refreshed NAMESPACE(quil_zqcnstset_aggregate_refreshed)
void quil_zqcnstset_aggregate_refreshed(sparsecnst out,const zqcnstset zqc,
                                     const int64_t *chalz,const polxvec chalx);

#endif
