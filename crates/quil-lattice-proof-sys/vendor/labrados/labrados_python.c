#include "labrados_python.h"
#include "malloc.h"
#include "fips202.h"
#include "comkey.h"
#include "timing.h"
#include "public_coefficient_encoding.h"
/* Only public statement coefficients use this shortcut. Keep the ordinary
 * conversion for every nonzero value and for the general multi-polynomial ABI.
 * Transcript hashing and the caller's conservative width assignment are
 * unchanged. Avoid K redundant NTTs for a literal zero polynomial. */
static int py_public_zero(const int64_t *values) {
  for(size_t i=0;i<N;i++)if(values[i]!=0)return 0;
  return 1;
}
/* QUIL_CANONICAL_STATEMENT_HASH_V2: initialized, explicit little-endian fields. */
static void py_hash_u64(shake128incctx *ctx,uint64_t value) {
  uint8_t bytes[8];
  for(int i=0;i<8;i++){bytes[i]=(uint8_t)value;value>>=8;}
  shake128_inc_absorb(ctx,bytes,sizeof(bytes));
}
static void py_hash_coeffs(shake128incctx *ctx,const int64_t *values,size_t count) {
  uint8_t bytes[3+N*QBYTES];
  while(count) {
    size_t take=count<N ? count : N;
    size_t encoded=quil_encode_public_coefficients(bytes,sizeof(bytes),values,take);
    if(!encoded)abort();
    shake128_inc_absorb(ctx,bytes,encoded);
    values+=take;count-=take;
  }
}

void py_init_witness(witness wt, size_t r, size_t n[]){
  size_t i, nn;

  witness_init(wt, r, r);

  nn = 0;
  for(i=0;i<r;i++){
    wt->n[i] = n[i];
    nn += n[i];
  }

  wt->s[0] = _aligned_alloc(64, nn * sizeof(poly));
  for(i=1;i<wt->r;i++){
    wt->s[i] = &wt->s[i-1][wt->n[i-1]];
  }
}

int py_set_witness_vector(
  witness wt, 
  size_t idx, 
  size_t n, 
  size_t deg, 
  const int64_t s[]
)
{
  if(idx >= wt->r) {
    fprintf(stderr,"ERROR in py_set_witness_vector(): "
                   "Witness vector %zu does not exist\n", idx);
    return 1;
  }
  if(n*deg != wt->n[idx]) {
    fprintf(stderr,"ERROR in py_set_witness_vector(): "
                   "Mismatch of witness vector length\n");
    return 2;
  }

  polyvec_fromint64vec(wt->s[idx], s, 1, n, deg, NULL);
  return 0;
}

int py_print_witness_vector(witness wt, size_t idx){
  if(idx >= wt->r){
    fprintf(stderr,"ERROR in py_print_witness_vector(): "
                   "Witness vector %zu does not exist\n", idx);
    return 1;
  }
  polyvec_print(wt->s[idx], 1, wt->n[idx]);
  return 0;
}

void py_init_statement(
  statement st, 
  size_t r, 
  size_t n[], 
  uint64_t normsq[],
  uint64_t normsq_req[], 
  normtype normty[], 
  size_t num_rq_cnst,
  size_t num_zq_cnst,
  size_t num_int_cnst
)
{
  size_t i;

  statement_init(st, r, r);
  for(i=0;i<r;i++){
    st->n[i] = n[i];
    st->normsq[i] = normsq[i];
    st->normsq_req[i] = normsq_req[i];
    st->normty[i] = normty[i];
  }
  
  rqcnstset_init(st->rqcnst, num_rq_cnst, 0);
  st->rqcnst->nsparse = 0; // update when appending
  zqcnstset_init(st->zqcnst, 0, num_zq_cnst, 0, 0, num_int_cnst);
  st->zqcnst->nint = 0; // update when appending

  shake128incctx hash;
  static const uint8_t domain[]="quil/native-public-statement/v6";
  shake128_inc_init(&hash);
  shake128_inc_absorb(&hash,domain,sizeof(domain));
  py_hash_u64(&hash,N);py_hash_u64(&hash,PS_Q);
  py_hash_u64(&hash,r);py_hash_u64(&hash,num_rq_cnst);
  py_hash_u64(&hash,num_zq_cnst);py_hash_u64(&hash,num_int_cnst);
  for(i=0;i<r;i++) {
    py_hash_u64(&hash,n[i]);py_hash_u64(&hash,normsq[i]);
    py_hash_u64(&hash,normsq_req[i]);py_hash_u64(&hash,normty[i]);
  }
  shake128_inc_finalize(&hash);shake128_inc_squeeze(st->h,HASHLEN,&hash);

  comkey_init(1);
}

int py_append_constraint(statement st, size_t nvec, const size_t idx[],
                         const size_t n[], size_t deg, int64_t *phi, int64_t *b,
                         int full) {
  return py_append_constraint_with_offsets(st,nvec,idx,n,deg,phi,b,full,NULL);
}

int py_append_constraint_with_offsets(statement st, size_t nvec, const size_t idx[],
    const size_t n[], size_t deg, int64_t *phi, int64_t *b, int full,
    const size_t *cached_offsets) {
  return py_append_constraint_with_cache(st,nvec,idx,n,deg,phi,b,full,
                                        cached_offsets,NULL,NULL);
}

int py_append_constraint_with_cache(
  statement st,
  size_t nvec,
  const size_t idx[],
  const size_t n[],
  size_t deg,
  int64_t *phi,
  int64_t *b,
  int full,
  const size_t *cached_offsets,
  py_copy_public_coefficient copy_cached,
  void *cache
)
{
  size_t i, j, k, *allocated_offsets = NULL, off_tmp;
  const size_t *off = cached_offsets;
  sparsecnst *cnst;
  double width_unif = ldexp(1, 2*LOGQ);
  polz t[deg];
  shake128incctx shakectx;

  if(!full && deg > 1){
    fprintf(stderr, "ERROR in py_append_constraint(): "
                    "Degree of integer constraint is too large\n");
    return 1;
  }

  for(i=0;i<nvec;i++){
    j = idx[i];
    if(j >= st->r){
      fprintf(stderr, "ERROR in py_append_constraint(): "
                      "Witness vector %zu does not exist\n", j);
      return 2;
    }
    if(n[i]*deg != st->n[j]){
      fprintf(stderr, "ERROR in py_append_constraint(): "
                      "Mismatch in witness vector length (vector %zu)\n", j);
      return 3;
    }
  }

  if(!off){
    allocated_offsets = _malloc(st->r * sizeof(size_t));
    allocated_offsets[0] = 0;
    off_tmp = 0;
    for(i=1;i<st->r;i++){
      off_tmp += st->n[i-1];
      allocated_offsets[i] = off_tmp;
    }
    off = allocated_offsets;
  }
  
  if(full){
    cnst = &st->rqcnst->sparse[st->rqcnst->nsparse];
    st->rqcnst->nsparse++;
    st->rqcnst->sparse_nchal += deg;
  }
  else{
    cnst = &st->zqcnst->sparse[st->zqcnst->nsparse];
    st->zqcnst->nsparse++;
    st->zqcnst->sparse_nchal += deg;
  }
  
  sparsecnst_init(*cnst, deg);
  linfunc_init((*cnst)->lin, deg, nvec, nvec);

  shake128_inc_init(&shakectx);
  shake128_inc_absorb(&shakectx,st->h,HASHLEN);
  py_hash_u64(&shakectx,1);py_hash_u64(&shakectx,full);
  py_hash_u64(&shakectx,deg);py_hash_u64(&shakectx,nvec);
  for(i=0;i<nvec;i++){py_hash_u64(&shakectx,idx[i]);py_hash_u64(&shakectx,n[i]);}

  if(deg==1 && copy_cached && copy_cached(cache,(*cnst)->b,b)) {
    /* Exact public conversion reused; transcript absorption remains below. */
  } else if(deg==1 && py_public_zero(b)) {
    polxvec_setzero((*cnst)->b,0,1,1);
  } else {
    polzvec_fromint64vec(t, 1, deg, b);
    polzvec_topolxvec((*cnst)->b, t, 0, 1, deg);
  }
  polxvec_setwidths1((*cnst)->b, 0, 1, deg, width_unif);
  py_hash_coeffs(&shakectx,b,deg*N);
  
  for(i=0;i<nvec;i++){
    j = idx[i];
    (*cnst)->lin->off[i] = off[j];
    polxvec_init((*cnst)->lin->phi[i], st->n[j], 1);
    for(k=0;k<n[i];k++){
      if(deg==1 && n[i]==1 && copy_cached
         && copy_cached(cache,(*cnst)->lin->phi[i],phi)) {
        /* Only a complete single-polynomial output can use this cache. */
      } else if(deg==1 && py_public_zero(phi)) {
        polxvec_setzero((*cnst)->lin->phi[i],k,1,1);
      } else {
        polzvec_fromint64vec(t, 1, deg, phi);
        polzvec_topolxvec((*cnst)->lin->phi[i], t, deg*k, 1, deg);
      }
      py_hash_coeffs(&shakectx,phi,deg*N);
      phi += deg*N;
    }
    polxvec_setwidths1((*cnst)->lin->phi[i], 0, 1, st->n[j], width_unif);
  }

  shake128_inc_finalize(&shakectx);
  shake128_inc_squeeze(st->h, 16, &shakectx);

  free(allocated_offsets);
  return 0;
}

int py_append_quadratic(statement st, size_t nlin, size_t nprod,
                        const size_t idx_lin[], const size_t idx_prod1[],
                        const size_t idx_prod2[], const size_t len_phi[],
                        size_t deg, int64_t *a, int64_t *phi, int64_t *b) {
  return py_append_quadratic_with_offsets(st,nlin,nprod,idx_lin,idx_prod1,
                                         idx_prod2,len_phi,deg,a,phi,b,NULL);
}

int py_append_quadratic_with_offsets(
  statement st,
  size_t nlin,
  size_t nprod,
  const size_t idx_lin[],
  const size_t idx_prod1[],
  const size_t idx_prod2[],
  const size_t len_phi[],
  size_t deg,
  int64_t *a,
  int64_t *phi,
  int64_t *b,
  const size_t *cached_offsets
)
{
  size_t i, j, k;
  sparsecnst *cnst;
  shake128incctx shakectx;
  int ret;

  ret = py_append_constraint_with_offsets(st, nlin, idx_lin, len_phi, deg, phi, b, 1, cached_offsets);

  if(ret){
    fprintf(stderr, "ERROR in py_append_quadratic(): "
                    "error while creating the linear part of the constraint\n");
    return 1;
  }

  for(i=0;i<nprod;i++){
    j = idx_prod1[i];
    k = idx_prod2[i];
    if(j >= st->r){
      fprintf(stderr, "ERROR in py_append_quadratic(): "
                      "Witness vector %zu does not exist\n", j);
      return 2;
    }
    if(k >= st->r){
      fprintf(stderr, "ERROR in py_append_quadratic(): "
                      "Witness vector %zu does not exist\n", k);
      return 3;
    }
    if(st->n[j] != st->n[k]){
      fprintf(stderr, "ERROR in py_append_quadratic(): "
                      "Mismatch in witness lengths (vectors %zu, %zu)\n", j, k);
      return 4;
    }
  }

  cnst = &st->rqcnst->sparse[st->rqcnst->nsparse-1];

  quadfunc_init((*cnst)->quad, nprod, nprod);

  shake128_inc_init(&shakectx);
  shake128_inc_absorb(&shakectx,st->h,HASHLEN);
  py_hash_u64(&shakectx,2);py_hash_u64(&shakectx,nprod);
  for(i=0;i<nprod;i++){
    if(st->normsq[idx_prod1[i]] <= st->normsq[idx_prod2[i]]){
      (*cnst)->quad->rows[i] = idx_prod1[i];
      (*cnst)->quad->cols[i] = idx_prod2[i];
    }
    else{
      (*cnst)->quad->rows[i] = idx_prod2[i];
      (*cnst)->quad->cols[i] = idx_prod1[i];
    }
    
    polx_monomial((*cnst)->quad->coeffs[i], 0, a[i]);

    py_hash_u64(&shakectx,idx_prod1[i]);py_hash_u64(&shakectx,idx_prod2[i]);
    py_hash_coeffs(&shakectx,&a[i],1);
  }

  shake128_inc_finalize(&shakectx);
  shake128_inc_squeeze(st->h, 16, &shakectx);

  return 0;
}

int py_append_deg0_constraint(
  statement st,
  size_t idx,
  size_t deg
)
{
  size_t i, off;
  intcnst *cnst;

  if(idx >= st->r){
    fprintf(stderr, "ERROR in py_append_deg0_constraint(): "
                    "Witness vector %zu does not exist\n", idx);
    return 1;
  }
  if(st->n[idx] != deg){
    fprintf(stderr, "ERROR in py_append_deg0_constraint(): "
                    "Mismatch in witness degree (vector %zu\n)", idx);
    return 2;
  }

  cnst = &st->zqcnst->intc[st->zqcnst->nint];
  st->zqcnst->nint++;
  st->zqcnst->int_nchal += deg*N-1;

  off = 0;
  for(i=0;i<idx;i++){
    off += st->n[i];
  }
  (*cnst)->off = off;
  (*cnst)->rank = deg;

  return 0;
}

int py_gen_params(dch_pack_params pp, const statement ist, int zk, int debug){
  size_t pibits;
  timing time;

  timing_start(&time, "Parameter generation");

  if(dch_pack_params_gen(pp, &pibits, ist, zk)){
    return 1;
  }
  if(debug){
    dch_pack_params_print(pp);
  }

  timing_end(&time);
  timing_print(&time, 0);

  printf("Estimated proof size: %.2fKB\n", ((double) pibits)/8192);

  return 0;
}

int py_simple_verify(const statement st, const witness wt){
  return verify(st, wt);
}

int py_prove(
  dch_pack_proof pi,
  const statement ist, 
  const witness iwt,
  const dch_pack_params pp
)
{
  timing time;

  timing_buffer_init();

  timing_start(&time, "Prover");

  int status=dch_pack_prove(pi, ist, iwt, pp);

  timing_end(&time);
  timing_print(&time, 0);

  timing_buffer_flush();
  return status;
}

int py_verify(
  const statement ist, 
  const dch_pack_params pp, 
  const dch_pack_proof pi
)
{
  int ret;
  timing time;

  timing_buffer_init();

  timing_start(&time, "Verifier");

  ret = dch_pack_verify(ist, pp, pi);

  timing_end(&time);
  timing_print(&time, 0);

  timing_buffer_flush();

  return ret;
}

void py_free_witness(witness wt){
  witness_free(wt);
}

void py_free_statement(statement st){
  statement_free(st);
  comkey_free();
}

void py_free_params(dch_pack_params pp){
  dch_pack_params_free(pp);
}

void py_free_proof(dch_pack_proof pi){
  dch_pack_proof_free(pi);
}
