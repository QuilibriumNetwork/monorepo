#include <stdio.h>
#include "malloc.h"
#include "polx.h"
#include "polz.h"
#include "constraints.h"
#include "comkey.h"
#include "resource_trace.h"
#include "rotation_parallel.h"
#include "refresh_parallel.h"
#include "public_refresh.h"

/*
  Initializes quad to have length len, while allocating enough memory to support
  up to maxlen elements.
*/
void quadfunc_init(quadfunc quad, size_t len, size_t maxlen){
  quad->len = len;
  if(maxlen == 0){
    quad->rows = NULL;
    quad->cols = NULL;
    quad->coeffs = NULL;
  }
  else{
    quad->rows = _malloc(2*maxlen*sizeof(size_t));
    quad->cols = &quad->rows[maxlen];
    quad->coeffs = _aligned_alloc(64, maxlen*sizeof(polx));
  }
}

static void quadfunc_copy(quadfunc out, const quadfunc in){
  size_t i;

  quadfunc_init(out, in->len, in->len);
  for(i=0;i<in->len;i++){
    out->rows[i] = in->rows[i];
    out->cols[i] = in->cols[i];
    polx_copy(out->coeffs[i], in->coeffs[i]);
  }
}

static void quadfunc_copy2(quadfunc out, const quadfunc in, size_t maxlen){
  size_t i;

  quadfunc_init(out, in->len, maxlen);
  for(i=0;i<in->len;i++){
    out->rows[i] = in->rows[i];
    out->cols[i] = in->cols[i];
    polx_copy(out->coeffs[i], in->coeffs[i]);
  }
}

void quadfunc_free(quadfunc quad){
  free(quad->rows);
  free(quad->coeffs);
  quad->len = 0;
}

/* ev += quad(sx) */
void quadfunc_eval_add(
  polxvec ev, 
  const quadfunc quad, 
  const polxvec sx[]
)
{
  size_t i, j, k, len, off, chunk;
  polxvec sxj, sxk, tmp;
  polxvec_init(tmp, ev->len, 1);

  for(i=0;i<quad->len;i++) {
    j = quad->rows[i];
    k = quad->cols[i];
    len = MIN(sx[j]->len, sx[k]->len);

    off = 0;
    while(len > 0){
      chunk = MIN(1000 * ev->len, len);
      polxvec_init_subvec2(sxj, sx[j], off, 1, chunk);
      polxvec_init_subvec2(sxk, sx[k], off, 1, chunk);
      polxvec_sprod_extension(tmp, sxj, sxk);
      polxvec_refresh(tmp);
      polxvec_polx_mul_add(ev, quad->coeffs[i], tmp);
      polxvec_refresh(ev); //XXX required ?
      off += chunk;
      len -= chunk;
    }
  }
  polxvec_free(tmp);
}

/*
  r += c*a, where c->len == 1. The quadfunc r is assumed to have enough 
  allocated memory for the update.
*/
static void quadfunc_polxvec_mul_add(
  quadfunc r, 
  const polxvec c, 
  const quadfunc a
)
{
  size_t i,j;
  polxvec rj, ai;

  for(i=0;i<a->len;i++) {
    for(j=0;j<r->len;j++) {
      if(r->rows[j] == a->rows[i] && r->cols[j] == a->cols[i]) {
        polxvec_init_frompolx(rj, r->coeffs[j]);
        polxvec_init_frompolx(ai, a->coeffs[i]);
        polxvec_mul_add(rj, c, ai);
        break;
      }
    }
    if(j == r->len) {
      r->rows[j] = a->rows[i];
      r->cols[j] = a->cols[i];
      r->coeffs[j]->width = 0;
      polxvec_init_frompolx(rj, r->coeffs[j]);
      polxvec_init_frompolx(ai, a->coeffs[i]);
      polxvec_mul(rj, c, ai);
      r->len += 1;
    }
  }
}

/*
  r += s*a. The quadfunc r is assumed to have enough allocated memory for the 
  update.
*/
static void quadfunc_scale_add(quadfunc r, const quadfunc a, int64_t s) {
  size_t i,j;

  for(i=0;i<a->len;i++) {
    for(j=0;j<r->len;j++) {
      if(r->rows[j] == a->rows[i] && r->cols[j] == a->cols[i]) {
        polx_scale_add(r->coeffs[j],a->coeffs[i],s);
        break;
      }
    }
    if(j == r->len) {
      r->rows[j] = a->rows[i];
      r->cols[j] = a->cols[i];
      polx_scale(r->coeffs[j],a->coeffs[i],s);
      r->len += 1;
    }
  }
}

/*
  Initializes lin with the specified rank and nparts, while allocating enough
  memory to support up to maxnparts.
*/
void linfunc_init(linfunc lin, size_t rank, size_t nparts, size_t maxnparts){
  lin->rank = rank;
  lin->nparts = nparts;
  if(maxnparts > 0){
    lin->off = _malloc(maxnparts*(sizeof(size_t) + sizeof(polxvec)));
    lin->phi = (polxvec *) &lin->off[maxnparts];
  }
  else{
    lin->off = NULL;
    lin->phi = NULL;
  }
}

static void linfunc_copy(linfunc out, const linfunc in){
  size_t i;

  linfunc_init(out, in->rank, in->nparts, in->nparts);
  for(i=0;i<in->nparts;i++){
    out->off[i] = in->off[i];
    polxvec_init(out->phi[i], in->phi[i]->len, 1);
    polxvec_copy(out->phi[i], in->phi[i]);
  }
}

void linfunc_free(linfunc lin){
  size_t i;
  for(i=0;i<lin->nparts;i++){
    polxvec_free(lin->phi[i]);
  }
  free(lin->off);
  lin->nparts = 0;
}

/* ev += lin(sx) */
void linfunc_eval_add(polxvec ev, const linfunc lin, const polxvec sx){
  size_t i;
  polxvec sx_sv;

  for(i=0;i<lin->nparts;i++){
    polxvec_init_subvec2(sx_sv, sx, lin->off[i], 1, lin->phi[i]->len);
    polxvec_sprod_extension_add(ev, lin->phi[i], sx_sv);
  }
}

/*
  Initializes a zero sparse constraint, the vector b is allocated and set to 0.
*/
void sparsecnst_init(sparsecnst cnst, size_t rank){
  quadfunc_init(cnst->quad, 0, 0);
  linfunc_init(cnst->lin, rank, 0, 0);
  polxvec_init(cnst->b, rank, 1);
  polxvec_setzero(cnst->b, 0, 1, rank);
}

void sparsecnst_copy(sparsecnst out, const sparsecnst in){
  sparsecnst_init(out, in->b->len);
  quadfunc_copy(out->quad, in->quad);
  linfunc_copy(out->lin, in->lin);
  polxvec_copy(out->b, in->b);
}

void sparsecnst_borrow_public(sparsecnst out, const sparsecnst in){
  quadfunc_copy(out->quad, in->quad);
  linfunc_init(out->lin, in->lin->rank, in->lin->nparts, in->lin->nparts);
  for(size_t i=0;i<in->lin->nparts;i++){
    out->lin->off[i] = in->lin->off[i];
    *out->lin->phi[i] = *in->lin->phi[i];
    out->lin->phi[i]->alloc = 0;
  }
  *out->b = *in->b;
  out->b->alloc = 0;
}

void sparsecnst_copy2(sparsecnst out, const sparsecnst in, size_t maxlen){
  sparsecnst_init(out, in->b->len);
  quadfunc_copy2(out->quad, in->quad, maxlen);
  linfunc_copy(out->lin, in->lin);
  polxvec_copy(out->b, in->b);
}

void sparsecnst_free(sparsecnst cnst){
  quadfunc_free(cnst->quad);
  linfunc_free(cnst->lin);
  polxvec_free(cnst->b);
}

void sparsecnst_refresh(sparsecnst cnst){
  size_t i;

  for(i=0;i<cnst->quad->len;i++){
    polx_refresh(cnst->quad->coeffs[i]);
  }
  for(i=0;i<cnst->lin->nparts;i++){
    polxvec_refresh(cnst->lin->phi[i]);
  }
  polxvec_refresh(cnst->b);
}

/* 
  ev = cnst(sx)
  The parameters sxq and sxl are two views of the same witness vector sx:
    - sxq: array of the r polxvec that form the witness sx.
    - sxl: concatenation of all the polxvec that form the witness sx.
*/
void sparsecnst_eval(
  polxvec ev,
  const sparsecnst cnst,
  const polxvec sxq[],
  const polxvec sxl
)
{
  polxvec_setzero(ev, 0, 1, ev->len);
  
  quadfunc_eval_add(ev, cnst->quad, sxq);
  linfunc_eval_add(ev, cnst->lin, sxl);
  polxvec_sub(ev, ev, cnst->b);
}

/* 
  When full=1, sparsecnst_check returns 1 if cnst(sx) = 0, and 0 
  otherwise. When full=0, sparse_check returns 1 if ctcoef(cnst(sx)) = 0,
  and 0 otherwise.
  The parameters sxq and sxl are two views of the same witness vector sx:
    - sxq: array of the r polxvec that form the witness sx.
    - sxl: concatenation of all the polxvec that form the witness sx.
*/
int sparsecnst_check(
  const sparsecnst cnst,
  const polxvec sxq[],
  const polxvec sxl,
  int full
)
{
  int check;
  polxvec ev;

  polxvec_init(ev, cnst->lin->rank, 1);
  sparsecnst_eval(ev, cnst, sxq, sxl);
  if(full){
    check = polxvec_iszero(ev);
  }
  else{
    check = polxvec_iszero_constcoeff(ev, 0);
  }
  polxvec_free(ev);
  return check;
}

/*
  The polxvec b is seen as a vector of polynomials in a higher degree ring,
  where the degree is the smallest power of 2 greater or equal to the rank,
  and the rank is a->len. Each such polynomial is expanded into a rotation
  matrix, where the number of rows is equal to the rank, and the number of
  columns is equal to the degree, except for the last polynomial, where the
  number of columns will be truncated to match the length of r. Each such
  rotation matrix is aggregated using the polynomial challenges in a and added
  to the corresponding subvector in r.
*/
void polxvec_rotation_aggregate_add(
  polxvec r, 
  const polxvec a, 
  const polxvec b
)
{
  size_t rank, deg, off, row, col, ncol, len;
  polxvec r_sv, a_sv, b_sv, tutl, tu, tl, tu_sv, tl_sv, tmp, tmp_sv;
  polx x;
  polx_monomial(x, 1, 1);

  rank = a->len;
  deg = next2power(rank);
  polxvec_init(tutl, 2*deg, 1);
  polxvec_init(tmp, deg, 1);

  off = 0;
  len = r->len;
  while(len > 0){
    ncol = MIN(deg, len);
    polxvec_init_subvec2(b_sv, b, off, 1, deg);
    polxvec_init_subvec2(r_sv, r, off, 1, ncol);
    polxvec_setzero(tutl, 0, 1, 2*ncol);
    polxvec_init_subvec2(tu, tutl, 0, 1, ncol);
    polxvec_init_subvec2(tl, tutl, ncol, 1, ncol);

    for(row=0;row<rank;row++){
      polxvec_init_subvec2(tmp_sv, tmp, 0, 1, deg);
      polxvec_init_subvec2(a_sv, a, row, 1, 1);
      polxvec_mul(tmp_sv, a_sv, b_sv);
      // Normalize each product before summing conservative full-width bounds.
      polxvec_refresh(tmp_sv);
                  
      for(col=0;col<ncol;col++){
        if(col<=row){
          // tl[col] += tmp[row-col]
          polxvec_init_subvec2(tl_sv, tl, col, 1, 1);
          polxvec_init_subvec2(tmp_sv, tmp, row-col, 1, 1);
          polxvec_add(tl_sv, tl_sv, tmp_sv);
        }
        else{
          // tu[col] += tmp[deg+row-col]
          polxvec_init_subvec2(tu_sv, tu, col, 1, 1);
          polxvec_init_subvec2(tmp_sv, tmp, deg+row-col, 1, 1);
          polxvec_add(tu_sv, tu_sv, tmp_sv);
        }
      }
    }
    polxvec_polx_mul_add(r_sv, x, tu);
    polxvec_add(r_sv, r_sv, tl);
    off += deg;
    len -= ncol;
  }
  
  polxvec_free(tutl);
  polxvec_free(tmp);
}


/*
  out += c*in, where c->len == in->lin->rank.
*/
static void sparsecnst_polxvec_mul_add(
  sparsecnst out,
  const polxvec c,
  const sparsecnst in
)
{
  size_t i;
  polxvec outphi;

  if(in->lin->rank == 1){
    quadfunc_polxvec_mul_add(out->quad, c, in->quad);
  }

  polxvec_sprod_add(out->b, c, in->b);

  for(i=0;i<in->lin->nparts;i++){
    polxvec_init_subvec2(outphi, out->lin->phi[0], in->lin->off[i], 1,
                        in->lin->phi[i]->len);
    if(in->lin->rank == 1){
      polxvec_mul_add(outphi, c, in->lin->phi[i]);
    }
    else{
      polxvec_rotation_aggregate_add(outphi, c, in->lin->phi[i]);
    }
  }
}

/*
  out += s*in
*/
static void sparsecnst_scale_add(
  sparsecnst out,
  const sparsecnst in,
  int64_t s,
  int zero_rhs
)
{
  size_t i;
  polxvec outphi;
  
  quadfunc_scale_add(out->quad, in->quad, s);

  if(!zero_rhs)polxvec_scale_add(out->b, in->b, s);

  for(i=0;i<in->lin->nparts;i++){
    polxvec_init_subvec2(outphi, out->lin->phi[0], in->lin->off[i], 1,
                        in->lin->phi[i]->len);
    polxvec_scale_add(outphi, in->lin->phi[i], s);
  }
}

/* 
  Add aggregation of all the input constraints into a single constraint.
    - out: single output constraint, over the base ring, with rank 1, and one
      part such that off[0] is 0 and phi[0]->len is the length of the witness.
    - in: array of input constraints.
    - ncnst: number of input constraints.
    - chal: polynomial challenges, used when full=1. In that case, there are
      as many challenges as the sum of the ranks of the input constraints.
    - chalz: integer scalar challenges, used when full=0. In that case, there 
      are as many challenges as the number of input constraints.
    - full: when set to 1, the constraints hold over the full ring, and are
      aggregated with the polynomial challenges in chal. Otherwise, the
      constraints only need to hold when looking at the constant coefficient, 
      and the aggregation is done with the integer scalars in chalz.
*/
void sparsecnst_aggregate_add(
  sparsecnst out, 
  const sparsecnst *in, 
  size_t ncnst, 
  const polxvec chal, 
  const int64_t *chalz, 
  int full
)
{
  size_t i, off;
  polxvec chal_sv;

  off = 0;
  for(i=0;i<ncnst;i++){
    if(full){
      polxvec_init_subvec2(chal_sv, chal, off, 1, in[i]->lin->rank);
      sparsecnst_polxvec_mul_add(out, chal_sv, in[i]);
    }
    else{
      sparsecnst_scale_add(out, in[i], chalz[off],0);
    }
    off += in[i]->lin->rank;

  }
}

/*
  Initializes cnst with the specified rank, ncom and nphi, while allocating
  enough memory to support up to maxnphi parts.
*/
void comcnst_init(
  comcnst cnst, 
  size_t rank, 
  size_t ncom, 
  size_t nphi, 
  size_t maxnphi
)
{
  size_t i;

  cnst->rank = rank;
  polxvec_init(cnst->b, rank, 1);

  cnst->ncom = ncom;
  cnst->comk_off = _malloc(ncom*(3*sizeof(size_t) + sizeof(int64_t)));
  cnst->comw_off = &cnst->comk_off[ncom];
  cnst->comw_len = &cnst->comw_off[ncom];
  cnst->scalar = (int64_t *) &cnst->comw_len[ncom];

  cnst->nphi = nphi;
  cnst->phiw_off = _malloc(maxnphi*(sizeof(size_t) + sizeof(polxvec)));
  cnst->phi = (polxvec *) &cnst->phiw_off[maxnphi];

  for(i=0;i<ncom;i++){
    cnst->scalar[i] = 1;
  }
}

void comcnst_copy(comcnst out, const comcnst in){
  size_t i;

  comcnst_init(out, in->rank, in->ncom, in->nphi, in->nphi);
  for(i=0;i<in->ncom;i++){
    out->comk_off[i] = in->comk_off[i];
    out->comw_off[i] = in->comw_off[i];
    out->comw_len[i] = in->comw_len[i];
    out->scalar[i] = in->scalar[i];
  }
  for(i=0;i<in->nphi;i++){
    out->phiw_off[i] = in->phiw_off[i];
    polxvec_init(out->phi[i], in->phi[i]->len, 1);
    polxvec_copy(out->phi[i], in->phi[i]);
  }
}

void comcnst_free(comcnst cnst){
  size_t i;
  polxvec_free(cnst->b);
  free(cnst->comk_off);
  
  for(i=0;i<cnst->nphi;i++){
    polxvec_free(cnst->phi[i]);
  }
  free(cnst->phiw_off);

  cnst->ncom = 0;
  cnst->nphi = 0;
}

/*
  ev = cnst(sx)
*/
void comcnst_eval(polxvec ev, const comcnst cnst, const polxvec sx){
  size_t i, j, rank;
  polxvec tmp, comkey_sv, sx_sv, phi_sv;

  rank = cnst->rank;
  polxvec_setzero(ev, 0, 1, rank);
  polxvec_init(tmp, rank, 1);

  for(i=0;i<cnst->ncom;i++){
    polxvec_init_subvec2(comkey_sv, comkey, cnst->comk_off[i], 1,
                        comkey->len - cnst->comk_off[i]);
    polxvec_init_subvec2(sx_sv, sx, cnst->comw_off[i], 1, cnst->comw_len[i]);
    if(cnst->scalar[i] == 1){
      polxvec_sprod_extension_add(ev, comkey_sv, sx_sv);
    }
    else{
      polxvec_sprod_extension(tmp, comkey_sv, sx_sv);
      polxvec_scale_add(ev, tmp, cnst->scalar[i]);
    }
  }

  for(i=0;i<cnst->nphi;i++){
    for(j=0;j<cnst->phi[i]->len;j++){
      polxvec_init_subvec2(sx_sv, sx, cnst->phiw_off[i] + j*rank, 1, rank);
      polxvec_init_subvec2(phi_sv, cnst->phi[i], j, 1, 1);
      polxvec_mul_add(ev, phi_sv, sx_sv);
    }
  }

  polxvec_sub(ev, ev, cnst->b);

  polxvec_free(tmp);
}

/*
  Returns 1 if cnst(sx) = 0; otherwise returns 0.
*/
int comcnst_check(const comcnst cnst, const polxvec sx){
  int check;
  polxvec ev;

  polxvec_init(ev, cnst->rank, 1);
  comcnst_eval(ev, cnst, sx);
  check = polxvec_iszero(ev);
  polxvec_free(ev);

  return check;
}

/*
  out += c*in
*/
static void comcnst_polxvec_mul_add(
  sparsecnst out,
  polxvec c,
  const comcnst in
)
{
  size_t i, j;
  polxvec inphi, outphi, tmp;

  polxvec_init(tmp, c->len, 1);

  polxvec_sprod_add(out->b, c, in->b);
  polxvec_refresh(out->b);

  for(i=0;i<in->ncom;i++){
    polxvec_init_subvec2(inphi, comkey, in->comk_off[i], 1,
                        comkey->len - in->comk_off[i]);
    polxvec_init_subvec2(outphi, out->lin->phi[0], in->comw_off[i], 1,
                        in->comw_len[i]);
    const char *trace=getenv("QUIL_NATIVE_RESOURCE_TRACE");
    if(trace && !strcmp(trace,"1")) {
      fprintf(stderr,"quil_native_rotation_shape length=%zu rank=%zu degree=%zu\n",
              outphi->len,c->len,next2power(c->len));
    }
    quil_resource_trace("commitment_rotation_begin");
    if(in->scalar[i] == 1){
      quil_polxvec_parallel_rotation_add(outphi, c, inphi);
    }
    else{
      polxvec_scale(tmp, c, in->scalar[i]);
      polxvec_refresh(tmp); // FIX: needed but assertion not triggered
      quil_polxvec_parallel_rotation_add(outphi, tmp, inphi);
    }
    quil_resource_trace("commitment_rotation_end");
    quil_resource_trace("commitment_refresh_begin");
    // Rotation workers have joined; this output slice is exclusively owned.
    quil_polxvec_parallel_refresh(outphi);
    quil_resource_trace("commitment_refresh_end");
  }

  quil_resource_trace("commitment_phi_begin");
  for(i=0;i<in->nphi;i++){
    for(j=0;j<in->phi[i]->len;j++){
      polxvec_init_subvec2(inphi, in->phi[i], j, 1, 1);
      polxvec_init_subvec2(outphi, out->lin->phi[0], in->phiw_off[i]+j*in->rank,
                          1, in->rank);
      polxvec_mul_add(outphi, inphi, c);
      polxvec_refresh(outphi);
    }
  }

  quil_resource_trace("commitment_phi_end");
  polxvec_free(tmp);
}

/* 
  Add aggregation of all the input commitment constraints into a single sparse
  constraint.
    - out: output sparse constraint, over the base ring, with rank 1, and one
      part such that off[0] is 0 and phi[0]->len is the length of the witness.
    - in: array of input commitment constraints.
    - ncnst: number of input constraints.
    - chal: vecor of polynomial challenges used to aggregate. There are as many 
      challenges as the sum of the ranks of the input constraints.
*/
void comcnst_aggregate_add(
  sparsecnst out, 
  const comcnst *in, 
  size_t ncnst, 
  const polxvec chal
)
{
  size_t i, off;
  polxvec chal_sv;

  off = 0;
  for(i=0;i<ncnst;i++){
    polxvec_init_subvec2(chal_sv, chal, off, 1, in[i]->rank);
    comcnst_polxvec_mul_add(out, chal_sv, in[i]);
    off += in[i]->rank;
  }
}

void sigmam1cnst_init(
  sigmam1cnst cnst, 
  size_t off1, 
  size_t off2, 
  size_t len,
  int mul
)
{
  cnst->off1 = off1;
  cnst->off2 = off2;
  cnst->len = len;
  cnst->mul = mul;
  if(mul){
    polxvec_init(cnst->c, 1, 1);
  }
}

void sigmam1cnst_copy(sigmam1cnst out, const sigmam1cnst in){
  sigmam1cnst_init(out, in->off1, in->off2, in->len, in->mul);
  if(in->mul){
    polxvec_copy(out->c, in->c);
  }
}

void sigmam1cnst_free(sigmam1cnst cnst){
  if(cnst->mul){
    polxvec_free(cnst->c);
    cnst->mul = 0;
  }
}

/*
  Returns 1 if cnst(sx)=0; otherwise returns 0.
*/
int sigmam1cnst_check(
  const sigmam1cnst cnst, 
  const polxvec sx
)
{
  int check;
  polxvec sx1, sx2, eq;

  polxvec_init_subvec2(sx1, sx, cnst->off1, 1, cnst->len);
  polxvec_init_subvec2(sx2, sx, cnst->off2, 1, cnst->len);
  polxvec_init(eq, cnst->len, 1);
  polxvec_sigmam1(eq, sx1);
  if(cnst->mul){
    polxvec_mul(eq, cnst->c, eq);
  }
  polxvec_sub(eq, eq, sx2);
  check = polxvec_iszero(eq);
  polxvec_free(eq);
  return check;
}

/* 
  Add aggregation of all the input sigmam1 constraints into a single sparse
  constraint.
    - out: output sparse constraint, over the base ring, with rank 1, and one
      part such that off[0] is 0 and phi[0]->len is the length of the witness.
    - in: array of input sigmam1 constraints.
    - ncnst: number of input constraints.
    - chalx: uniform polynomial challenges used to aggregate. The number of
      challenges is (sum_i in[i]->len)
*/
void sigmam1cnst_aggregate_add(
  sparsecnst out, 
  const sigmam1cnst *in, 
  size_t ncnst, 
  const polxvec chalx
)
{
  size_t i, off, maxlen;
  polxvec phi1, phi2, chalx_phi1, chalx_sv;

  if(ncnst == 0){
    return;
  }

  maxlen = 0;
  for(i=0;i<ncnst;i++){
    maxlen = MAX(maxlen, in[i]->len);
  }

  polxvec_init(chalx_phi1, maxlen, 1);

  off = 0;
  for(i=0;i<ncnst;i++){
    polxvec_init_subvec(chalx_phi1, chalx_phi1, 0, 1, in[i]->len);
    polxvec_init_subvec2(chalx_sv, chalx, off, 1, in[i]->len);
    polxvec_init_subvec2(phi1, out->lin->phi[0], in[i]->off1, 1, in[i]->len);
    polxvec_init_subvec2(phi2, out->lin->phi[0], in[i]->off2, 1, in[i]->len);

    polxvec_add(phi2, phi2, chalx_sv);

    if(in[i]->mul){
      polxvec_mul(chalx_phi1, in[i]->c, chalx_sv);
      polxvec_sigmam1(chalx_phi1, chalx_phi1);
    }
    else{
      polxvec_sigmam1(chalx_phi1, chalx_sv);
    }
    polxvec_sub(phi1, phi1, chalx_phi1);

    off += in[i]->len;
  }

  polxvec_free(chalx_phi1);
}

void intcnst_copy(intcnst out, const intcnst in){
  out->off = in->off;
  out->rank = in->rank;
}

int intcnst_check(const intcnst cnst, const polxvec sx){
  size_t i, j;
  polz sxz;
  polxvec pol;
  int check;

  check = 1;

  polzvec_frompolxvec(&sxz, sx, cnst->off, 1, 1);
  for(i=0;i<L;i++){
    for(j=1;j<N;j++){
      if(sxz->limbs[i]->c[j] != 0){
        check = 0;
      }
    }
  }

  if(cnst->rank > 1){
    polxvec_init_subvec2(pol, sx, cnst->off+1, 1, cnst->rank-1);
    check &= polxvec_iszero(pol);
  }

  return check;
}

void intcnst_aggregate_add(
  sparsecnst out, 
  const intcnst *in, 
  size_t ncnst,
  const int64_t *chalz
)
{
  size_t i, j, k, chalz_off;
  int64_t phi64[N];
  polxvec phi_in, phi_out;
  double width = 0x1p64; // 2**64

  polxvec_init(phi_in, 1, 1);

  chalz_off = 0;
  for(i=0;i<ncnst;i++){
    for(j=0;j<in[i]->rank;j++){
      phi64[0] = (j == 0) ? 0 : chalz[chalz_off++];
      for(k=1;k<N;k++){
        phi64[k] = chalz[chalz_off++];
      }
      polxvec_fromint64vec2(phi_in, phi64, 1, 1, width);
      polxvec_init_subvec2(phi_out, out->lin->phi[0], in[i]->off+j, 1, 1);
      polxvec_add(phi_out, phi_out, phi_in);
    }
  }

  polxvec_free(phi_in);
}

void rqcnstset_init(rqcnstset rqc, size_t nsparse, size_t ncommit){
  rqc->nsparse = nsparse;
  rqc->ncom = ncommit;
  if(nsparse + ncommit == 0){
    rqc->sparse = NULL;
  }
  else{
    rqc->sparse = _malloc(nsparse*sizeof(sparsecnst) + ncommit*sizeof(comcnst));
    rqc->com = (comcnst *) &rqc->sparse[nsparse];
  }
  rqc->sparse_nchal = 0;
  rqc->com_nchal = 0;
}

void rqcnstset_free(rqcnstset rqc){
  size_t i;

  for(i=0;i<rqc->nsparse;i++){
    sparsecnst_free(rqc->sparse[i]);
  }
  for(i=0;i<rqc->ncom;i++){
    comcnst_free(rqc->com[i]);
  }
  free(rqc->sparse);

  rqc->nsparse = 0;
  rqc->sparse_nchal = 0;
  rqc->ncom = 0;
  rqc->com_nchal = 0;
}

/*
  Returns 1 if all the constraints in rqc are satisfied; otherwise returns 0.
  The parameters sxq and sxl are two views of the same witness vector sx:
    - sxq: array of the r polxvec that form the witness sx.
    - sxl: concatenation of all the polxvec that form the witness sx.
*/
int rqcnstset_check(
  const rqcnstset rqc, 
  const polxvec sxq[], 
  const polxvec sxl
)
{
  int check;
  size_t i;

  check = 1;
  for(i=0;i<rqc->nsparse;i++){
    check &= sparsecnst_check(rqc->sparse[i], sxq, sxl, 1);
  }
  for(i=0;i<rqc->ncom;i++){
    check &= comcnst_check(rqc->com[i], sxl);
  }
  return check;
}

/* 
  Add aggregation of all the constraints in rqc into a single sparse constraint.
    - out: output sparse constraint, over the base ring, with rank 1, and one
      part such that off[0] is 0 and phi[0]->len is the length of the witness.
    - rqc: input set of Rq constraints.
    - chal: vector  of polynomial challenges used to aggregate. The number of
      challenges is rqc->sparse_nchal + rqc->com_nchal.
*/
void rqcnstset_aggregate_add(
  sparsecnst out, 
  const rqcnstset rqc, 
  const polxvec chal
)
{
  polxvec chal_sv;

  if(rqc->nsparse) {
    polxvec_init_subvec2(chal_sv, chal, 0, 1, rqc->sparse_nchal);
    quil_resource_trace("rq_sparse_begin");
    sparsecnst_aggregate_add(out, rqc->sparse, rqc->nsparse, chal_sv, NULL, 1);
    quil_resource_trace("rq_sparse_end");
  }

  // A view at the end of a vector is invalid, even if there are no terms
  // to aggregate. Linear-only statements legitimately have no commitments.
  if(rqc->ncom) {
    polxvec_init_subvec2(chal_sv, chal, rqc->sparse_nchal, 1, rqc->com_nchal);
    quil_resource_trace("rq_commitment_begin");
    comcnst_aggregate_add(out, rqc->com, rqc->ncom, chal_sv);
    quil_resource_trace("rq_commitment_end");
  }
}

void zqcnstset_init(
  zqcnstset zqc, 
  size_t nsparse, 
  size_t maxnsparse, 
  size_t nsigmam1, 
  size_t maxnsigmam1,
  size_t nint
)
{
  zqc->nsparse = nsparse;
  zqc->nsigmam1 = nsigmam1;
  zqc->nint = nint;
  
  if(maxnsparse + maxnsigmam1 + nint == 0){
    zqc->sparse = NULL;
  }
  else{
    zqc->sparse = _malloc(maxnsparse * sizeof(sparsecnst)
                        + maxnsigmam1 * sizeof(sigmam1cnst)
                        + nint * sizeof(intcnst));
    zqc->sigmam1 = (sigmam1cnst *) &zqc->sparse[maxnsparse];
    zqc->intc = (intcnst *) &zqc->sigmam1[maxnsigmam1];
  }
  zqc->sparse_nchal = 0;
  zqc->sigmam1_nchal = 0;
  zqc->int_nchal = 0;
#ifndef NDEBUG
  zqc->maxnsparse = maxnsparse;
  zqc->maxnsigmam1 = maxnsigmam1;
#endif
}

void zqcnstset_free(zqcnstset zqc){
  size_t i;

  for(i=0;i<zqc->nsparse;i++){
    sparsecnst_free(zqc->sparse[i]);
  }
  for(i=0;i<zqc->nsigmam1;i++){
    sigmam1cnst_free(zqc->sigmam1[i]);
  }
  free(zqc->sparse);

  zqc->nsparse = 0;
  zqc->sparse_nchal = 0;
  zqc->nsigmam1 = 0;
  zqc->sigmam1_nchal = 0;
#ifndef NDEBUG
  zqc->maxnsparse = 0;
  zqc->maxnsigmam1 = 0;
#endif
}

/*
  Returns 1 if all the constraints in zqc are satisfied; otherwise returns 0.
  The parameters sxq and sxl are two views of the same witness vector sx:
    - sxq: array of the r polxvec that form the witness sx.
    - sxl: concatenation of all the polxvec that form the witness sx.
*/
int zqcnstset_check(
  const zqcnstset zqc, 
  const polxvec sxq[], 
  const polxvec sxl
)
{
  int check;
  size_t i;

  check = 1;
  for(i=0;i<zqc->nsparse;i++){
    check &= sparsecnst_check(zqc->sparse[i], sxq, sxl, 0);
  }
  for(i=0;i<zqc->nsigmam1;i++){
    check &= sigmam1cnst_check(zqc->sigmam1[i], sxl);
  }
  for(i=0;i<zqc->nint;i++){
    check &= intcnst_check(zqc->intc[i], sxl);
  }
  return check;
}

/* 
  Add aggregation of all the constraints in zqc into a single sparse constraint.
    - out: output sparse constraint, over the base ring, with rank 1, and one
      part such that off[0] is 0 and phi[0]->len is the length of the witness.
    - zqc: input set of Zq constraints.
    - chalz: integer scalar challenges used to aggregate zqc->sparse. The number 
      of challenges is zqc->sparse_nchal.
    - chalx: polynomial challenges used to aggregate zqc->sigmam1. The length of 
      chalx is zqc->sigmam1_nchal.
*/
void zqcnstset_aggregate_add(
  sparsecnst out, 
  const zqcnstset zqc, 
  const int64_t *chalz,
  const polxvec chalx
)
{
  sparsecnst_aggregate_add(out, zqc->sparse, zqc->nsparse, NULL, chalz, 0);

  sigmam1cnst_aggregate_add(out, zqc->sigmam1, zqc->nsigmam1, chalx);

  intcnst_aggregate_add(out, zqc->intc, zqc->nint, &chalz[zqc->sparse_nchal]);
}

/* Worker-only variant: input is immutable and disjoint from the owning output.
 * Skipping an exact zero RHS omits only its artificial width accumulation.
 * A mandatory final refresh restores the same canonical values and widths. */
void quil_zqcnstset_aggregate_refreshed(sparsecnst out,const zqcnstset zqc,
                                     const int64_t *chalz,const polxvec chalx) {
  const char *trace_env=getenv("QUIL_NATIVE_RESOURCE_TRACE");
  int trace=trace_env && !strcmp(trace_env,"1");
  double marks[5]={0};
  if(trace)marks[0]=quil_resource_monotonic_seconds();
  static const unsigned char zero[sizeof(poly)]={0};
  const void *known_zero[K]={0};
  int have_zero=0;
  size_t off=0;
  for(size_t row=0;row<zqc->nsparse;row++) {
    const struct _sparsecnst *in=zqc->sparse[row];
    int rhs_zero=0;
    if(in->b->len==1) {
      rhs_zero=have_zero;
      for(size_t k=0;k<K && rhs_zero;k++)
        if(in->b->proj[k]!=known_zero[k])rhs_zero=0;
      if(!rhs_zero) {
        rhs_zero=1;
        for(size_t k=0;k<K;k++)
          if(memcmp(in->b->proj[k][0],zero,sizeof(poly))){rhs_zero=0;break;}
        if(rhs_zero) {
          for(size_t k=0;k<K;k++)known_zero[k]=in->b->proj[k];
          have_zero=1;
        }
      }
    }
    sparsecnst_scale_add(out,in,chalz[off],rhs_zero);
    off+=in->lin->rank;
  }
  if(trace)marks[1]=quil_resource_monotonic_seconds();
  sigmam1cnst_aggregate_add(out,zqc->sigmam1,zqc->nsigmam1,chalx);
  if(trace)marks[2]=quil_resource_monotonic_seconds();
  intcnst_aggregate_add(out,zqc->intc,zqc->nint,&chalz[zqc->sparse_nchal]);
  if(trace)marks[3]=quil_resource_monotonic_seconds();
  quil_public_sparsecnst_refresh(out);
  if(trace) {
    marks[4]=quil_resource_monotonic_seconds();
    int valid=marks[0]>0;
    for(size_t i=1;i<5;i++)if(marks[i]<marks[i-1])valid=0;
    if(valid)fprintf(stderr,"quil_native_zq_worker sparse_rows=%zu output_length=%zu sparse_seconds=%.6f sigma_seconds=%.6f integer_seconds=%.6f refresh_seconds=%.6f\n",
                     zqc->nsparse,out->lin->phi[0]->len,
                     marks[1]-marks[0],marks[2]-marks[1],
                     marks[3]-marks[2],marks[4]-marks[3]);
  }
}
