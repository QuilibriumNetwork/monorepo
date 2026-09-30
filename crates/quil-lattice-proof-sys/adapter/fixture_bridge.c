/* Benchmark-only opaque ABI over the pinned native frontend; public fixtures.
 * Native struct layouts stay in C, compiled against the actual N=256 headers.
 */
#if defined(DEBUG) || defined(NDEBUG)
#error "Native token proofs require assertions and prohibit internal debug dumps"
#endif
#include "resource_trace.h"
#include <stdlib.h>
#include <math.h>
#define QUIL_APPROX_GROUP 1024
#include <stdint.h>
#include "labrados_python.h"
#include "prg_stream.h"
#include "gaussian.h"
#include "fixture_proof_dump.h"
#include "fixture_proof_encode.h"
#include "coefficient_pool.h"
#include "private_mask_range.h"
#include "ntt_benchmark.h"
#include "shake_absorb_test.h"
#include "zq_parallel.h"
#include "refresh_parallel.h"
#include "jl_parallel.h"
#include "ldr_parallel.h"
#include "lnp_parallel.h"
#include "labrador.h"
#include "rotation_parallel.h"
#include "public_refresh.h"
typedef struct {
  statement st;
  size_t *offsets;
  fixture_coefficient_pool coefficients;
  witness wt;
  size_t count,next,ring_limit,scalar_limit,ring_seen,scalar_seen,checks;
  size_t short_from;
  uint64_t *short_normsq;
  int checked,witness_dropped;
} fixture_context;
static void fixture_share_row(fixture_context *ctx,struct _sparsecnst *row,size_t count,
                              const int64_t *coeffs,const int64_t *rhs) {
  for(size_t i=0;i<count;i++)fixture_pool_share(&ctx->coefficients,row->lin->phi[i],coeffs+i*N);
  fixture_pool_share(&ctx->coefficients,row->b,rhs);
}
/* Witnesses [0,short_from) are exact binary polynomials; [short_from,count)
 * are approximate-norm (L2APPROX) polynomials with the given squared l2 bounds.
 * short_normsq may be NULL only when short_from==count. */
static void *fixture_new(size_t count,size_t rings,size_t scalars,size_t short_from,const uint64_t *short_normsq,int with_witness) {
  if(N!=256 || !count || count>500000 || rings>400000 || scalars>2000000) return NULL;
  if(short_from>count || (short_from<count && !short_normsq)) return NULL;
  for(size_t i=short_from;i<count;i++) if(short_normsq[i-short_from]<N || short_normsq[i-short_from]>=(1ULL<<62)) return NULL;
  quil_resource_trace("context_allocate_begin");
  fixture_context *ctx=calloc(1,sizeof(*ctx));
  size_t *n=malloc(count*sizeof(*n));
  uint64_t *norm=malloc(count*sizeof(*norm)),*required=calloc(count,sizeof(*required));
  normtype *types=malloc(count*sizeof(*types));
  if(!ctx || !n || !norm || !required || !types) abort();
  for(size_t i=0;i<count;i++){n[i]=1;norm[i]=N;types[i]=BIN;}
  /* Approximate-norm vectors: the honest witness satisfies normsq; the proof
   * only guarantees normsq * JL_INF_SLACK^2 for an extracted witness, and the
   * parameter generator refuses tighter requirements. Consecutive vectors merge
   * into one part while the smallest requirement covers the group's summed
   * guarantee, so the requirement carries a group budget of QUIL_APPROX_GROUP
   * vectors (the relation declares uniform limb bounds). The extracted witness
   * of a group is only bounded jointly; the SIS argument uses that bound.
   * Both values enter the statement hash. */
  for(size_t i=short_from;i<count;i++){
    norm[i]=short_normsq[i-short_from];types[i]=L2APPROX;
    required[i]=QUIL_APPROX_GROUP*(uint64_t)ceil((double)norm[i]*JL_INF_SLACK*JL_INF_SLACK);
  }
  ctx->short_from=short_from;
  if(short_from<count){ctx->short_normsq=malloc((count-short_from)*sizeof(uint64_t));if(!ctx->short_normsq)abort();memcpy(ctx->short_normsq,short_normsq,(count-short_from)*sizeof(uint64_t));}
  if(with_witness)py_init_witness(ctx->wt,count,n);
  ctx->witness_dropped=!with_witness;
  py_init_statement(ctx->st,count,n,norm,required,types,rings,scalars,0);
  ctx->count=count;ctx->ring_limit=rings;ctx->scalar_limit=scalars;
  // Every vector in this adapter has length one. Retain its fixed prefix
  // offsets once instead of rebuilding count offsets for every constraint.
  ctx->offsets=n;
  for(size_t i=0;i<count;i++)ctx->offsets[i]=i;
  free(norm);free(required);free(types);
  quil_resource_trace("context_allocate_end");
  return ctx;
}
void *quil_fixture_new(size_t count,size_t rings,size_t scalars) {
  return fixture_new(count,rings,scalars,count,NULL,1);
}
void *quil_fixture_new_public(size_t count,size_t rings,size_t scalars) {
  return fixture_new(count,rings,scalars,count,NULL,0);
}
void *quil_fixture_new_typed(size_t count,size_t rings,size_t scalars,size_t short_from,const uint64_t *short_normsq,int with_witness) {
  return fixture_new(count,rings,scalars,short_from,short_normsq,with_witness ? 1 : 0);
}
int quil_fixture_binary_domain(void *opaque) {
  fixture_context *ctx=opaque;
  if(!ctx->witness_dropped || ctx->next>=ctx->short_from)return 1;
  ctx->next++;
  return 0;
}
int quil_fixture_binary(void *opaque,const int64_t *values) {
  fixture_context *ctx=opaque;
  if(ctx->witness_dropped || ctx->next>=ctx->short_from) return 1;
  for(size_t i=0;i<N;i++) if(values[i]!=0 && values[i]!=1) return 1;
  ctx->checked=0;
  int ret=py_set_witness_vector(ctx->wt,ctx->next,1,1,values);
  if(!ret)ctx->next++;
  return ret;
}
/* Approximate-norm witness: coefficients are signed integers whose squared
 * l2 norm must not exceed the bound declared at construction. */
int quil_fixture_short_domain(void *opaque) {
  fixture_context *ctx=opaque;
  if(!ctx->witness_dropped || ctx->next<ctx->short_from || ctx->next>=ctx->count)return 1;
  ctx->next++;
  return 0;
}
int quil_fixture_short(void *opaque,const int64_t *values) {
  fixture_context *ctx=opaque;
  if(ctx->witness_dropped || ctx->next<ctx->short_from || ctx->next>=ctx->count) return 1;
  unsigned __int128 normsq=0;
  for(size_t i=0;i<N;i++){ if(values[i]<=-(1LL<<31) || values[i]>=(1LL<<31)) return 1; normsq+=(unsigned __int128)((__int128)values[i]*values[i]); }
  if(normsq>ctx->short_normsq[ctx->next-ctx->short_from]) return 1;
  ctx->checked=0;
  int ret=py_set_witness_vector(ctx->wt,ctx->next,1,1,values);
  if(!ret)ctx->next++;
  return ret;
}
int quil_fixture_linear(void *opaque,size_t count,const size_t *indices,int64_t *coeffs,int64_t *rhs,int full) {
  fixture_context *ctx=opaque;
  if(!count || count>ctx->count || (full!=0 && full!=1)) return 1;
  if(full ? ctx->ring_seen>=ctx->ring_limit : ctx->scalar_seen>=ctx->scalar_limit) return 1;
  size_t *lengths=malloc(count*sizeof(*lengths));
  if(!lengths)abort();
  for(size_t i=0;i<count;i++){if(indices[i]>=ctx->next){free(lengths);return 1;}lengths[i]=1;}
  ctx->checked=0;
  ctx->coefficients.submitted_copy_count=0;
  int ret=py_append_constraint_with_cache(ctx->st,count,indices,lengths,1,coeffs,rhs,full,
      ctx->offsets,fixture_pool_copy_submitted,&ctx->coefficients);
  free(lengths);
  if(!ret){
    struct _sparsecnst *row=full ? ctx->st->rqcnst->sparse[ctx->ring_seen++]
                               : ctx->st->zqcnst->sparse[ctx->scalar_seen++];
    fixture_share_row(ctx,row,count,coeffs,rhs);
  }
  ctx->coefficients.submitted_copy_count=0;
  return ret;
}
int quil_fixture_quadratic(void *opaque,size_t nl,size_t nq,const size_t *linear,const size_t *left,const size_t *right,int64_t *a,int64_t *phi,int64_t *rhs) {
  fixture_context *ctx=opaque;
  if(!nl || nl>ctx->count || !nq || nq>ctx->count || ctx->ring_seen>=ctx->ring_limit)return 1;
  size_t *lengths=malloc(nl*sizeof(*lengths));if(!lengths)abort();
  for(size_t i=0;i<nl;i++){if(linear[i]>=ctx->next){free(lengths);return 1;}lengths[i]=1;}
  for(size_t i=0;i<nq;i++)if(left[i]>=ctx->next || right[i]>=ctx->next){free(lengths);return 1;}
  ctx->checked=0;
  int ret=py_append_quadratic_with_offsets(ctx->st,nl,nq,linear,left,right,lengths,1,a,phi,rhs,ctx->offsets);
  free(lengths);
  if(!ret){
    fixture_share_row(ctx,ctx->st->rqcnst->sparse[ctx->ring_seen++],nl,phi,rhs);
  }
  return ret;
}
int quil_fixture_check(void *opaque) {
  fixture_context *ctx=opaque;
  if(ctx->witness_dropped || ctx->next!=ctx->count || ctx->ring_seen!=ctx->ring_limit || ctx->scalar_seen!=ctx->scalar_limit)return 0;
  if(ctx->checked)return 1;
  ctx->checks++;
  ctx->checked=py_simple_verify(ctx->st,ctx->wt)==1;
  return ctx->checked;
}
size_t quil_fixture_check_count(void *opaque) {
  return ((fixture_context *)opaque)->checks;
}
static int fixture_prove(void *opaque,const char *path,uint8_t *bytes,size_t capacity,size_t *written,unsigned int error_stage) {
  fixture_context *ctx=opaque;
  if(written)*written=0;
  quil_resource_trace("assignment_check_begin");
  if(!quil_fixture_check(ctx))return 1;
  quil_resource_trace("assignment_check_end");
  dch_pack_params pp;
  dch_pack_proof proof;
  if(py_gen_params(pp,ctx->st,1,0))return 2;
  quil_resource_trace("parameters_ready");
  if(pp->pp_pack->zkp==NULL || pp->pp_pack->np==0 || pp->pp_pack->zkround>=pp->pp_pack->np) {
    py_free_params(pp);return 4;
  }
  // Explicit diagnostic entry point only: invalid M forces an error at one
  // of the three sampling decisions, without disabling masking or rejection.
  if(error_stage==1)pp->pp_pack->zkp[0]->capmp=0.5L;
  if(error_stage==2)pp->pp_pack->zkp[0]->capm2=0.5L;
  if(error_stage==3)pp->pp_pack->zkp[0]->capm1=0.5L;
  // No cached assignment result survives native proof construction.
  ctx->checked=0;
  quil_resource_trace("prove_begin");
  if(py_prove(proof,ctx->st,ctx->wt,pp)) {
    fixture_decoded_free(proof);py_free_params(pp);return 7;
  }
  quil_resource_trace("prove_end");
  if(path && !fixture_dump_proof(path,proof,pp)) {
    fixture_decoded_free(proof);py_free_params(pp);return 5;
  }
  if(bytes && !fixture_encode_proof(bytes,capacity,written,proof,pp)) {
    fixture_decoded_free(proof);py_free_params(pp);return 6;
  }
  quil_resource_trace("self_verify_begin");
  int valid=py_verify(ctx->st,pp,proof);
  quil_resource_trace("self_verify_end");
  fixture_decoded_free(proof);py_free_params(pp);
  if(!valid && written)*written=0;
  return valid ? 0 : 3;
}
int quil_fixture_prove_dump(void *opaque,const char *path) {
  return fixture_prove(opaque,path,NULL,0,NULL,0);
}
int quil_fixture_prove_encoded(void *opaque,uint8_t *bytes,size_t capacity,size_t *written) {
  if(!bytes || !written)return 6;
  return fixture_prove(opaque,NULL,bytes,capacity,written,0);
}
int quil_fixture_test_sampling_error(void *opaque,unsigned int stage,uint8_t *bytes,size_t capacity,size_t *written) {
  if(stage<1 || stage>3 || !bytes || !written)return -1;
  return fixture_prove(opaque,NULL,bytes,capacity,written,stage);
}
void quil_fixture_drop_witness(void *opaque) {
  fixture_context *ctx=opaque;
  if(ctx->witness_dropped)return;
  py_free_witness(ctx->wt);memset(ctx->wt,0,sizeof(witness));
  ctx->witness_dropped=1;ctx->checked=0;
}
int quil_fixture_verify_encoded(void *opaque,const uint8_t *bytes,size_t size) {
  fixture_context *ctx=opaque;
  if(ctx->next!=ctx->count || ctx->ring_seen!=ctx->ring_limit || ctx->scalar_seen!=ctx->scalar_limit)return 0;
  if(!bytes || size<40 || size>=FIXTURE_PROOF_LIMIT || memcmp(bytes,"QPF6\0\0\0\0",8))return 0;
  /* The gap from context_allocate_end to this marker includes public
   * relation submission. Separate it from parameter generation and decoding. */
  quil_resource_trace("verify_parameters_begin");
  const char *cache_trace=getenv("QUIL_NATIVE_RESOURCE_TRACE");
  if(cache_trace && !strcmp(cache_trace,"1")) {
    fprintf(stderr,"quil_native_coefficient_cache capacity=%u entries=%zu conversion_hits=%zu borrowers=%zu\n",
            (unsigned)FIXTURE_POOL_GENERAL_VALUES,ctx->coefficients.general_count,
            ctx->coefficients.conversion_hits,ctx->coefficients.count);
    fflush(stderr);
  }
  /* No assignment check and no access to ctx->wt: verification uses public st. */
  dch_pack_params params;
  if(py_gen_params(params,ctx->st,1,0))return 0;
  quil_resource_trace("verify_parameters_end");
  dch_pack_proof proof;
  quil_resource_trace("proof_decode_begin");
  if(!fixture_decode_proof(proof,params,bytes,size)){py_free_params(params);return 0;}
  quil_resource_trace("proof_decode_end");
  quil_resource_trace("public_verify_begin");
  int valid=py_verify(ctx->st,params,proof);
  quil_resource_trace("public_verify_end");
  quil_resource_trace("verify_workspace_free_begin");
  fixture_decoded_free(proof);py_free_params(params);
  quil_resource_trace("verify_workspace_free_end");
  return valid;
}
int quil_fixture_prove(void *opaque) {
  return quil_fixture_prove_dump(opaque,NULL);
}
void quil_fixture_free(void *opaque) {
  if(!opaque)return;
  fixture_context *ctx=opaque;
  fixture_pool_detach(&ctx->coefficients);
  py_free_statement(ctx->st);if(!ctx->witness_dropped)py_free_witness(ctx->wt);
  fixture_pool_free(&ctx->coefficients);free(ctx->offsets);free(ctx);
}

/* Deterministic ABI regression: cached and generic submission must produce
 * identical transcripts, offsets and polynomial projections, including
 * non-uniform vector lengths that are not used by the fixed-length adapter. */
static int fixture_same_vector(const polxvec a,const polxvec b) {
  if(a->len!=b->len)return 0;
  for(size_t i=0;i<a->len;i++) {
    size_t ai=a->off+i*a->stride,bi=b->off+i*b->stride;
    if(a->widths[ai]!=b->widths[bi])return 0;
    for(size_t k=0;k<K;k++)
      if(memcmp(a->proj[k][ai],b->proj[k][bi],sizeof(poly)))return 0;
  }
  return 1;
}
int quil_fixture_test_cached_offsets(void) {
  statement st[2];
  size_t n[3]={2,1,2},offsets[3]={0,2,3},idx[2]={2,0},lengths[2]={2,2};
  size_t left[1]={0},right[1]={2};
  uint64_t norms[3]={512,256,512},required[3]={0};
  normtype types[3]={BIN,BIN,BIN};
  int64_t phi[4*N]={0},rhs[N]={0},products[1]={-1};
  phi[0]=3;phi[N+7]=-2;phi[2*N+255]=1;phi[3*N+19]=5;
  int ok=1;
  for(size_t mode=0;mode<2;mode++) {
    py_init_statement(st[mode],3,n,norms,required,types,2,1,0);
    for(int full=0;full<=1;full++) {
      int status=mode ? py_append_constraint_with_offsets(st[mode],2,idx,lengths,1,phi,rhs,full,offsets)
                      : py_append_constraint(st[mode],2,idx,lengths,1,phi,rhs,full);
      if(status)ok=0;
    }
    int status=mode ? py_append_quadratic_with_offsets(st[mode],2,1,idx,left,right,lengths,1,products,phi,rhs,offsets)
                    : py_append_quadratic(st[mode],2,1,idx,left,right,lengths,1,products,phi,rhs);
    if(status)ok=0;
  }
  if(memcmp(st[0]->h,st[1]->h,HASHLEN))ok=0;
  for(size_t row=0;row<3;row++) {
    struct _sparsecnst *a=row<2 ? st[0]->rqcnst->sparse[row] : st[0]->zqcnst->sparse[0];
    struct _sparsecnst *b=row<2 ? st[1]->rqcnst->sparse[row] : st[1]->zqcnst->sparse[0];
    if(a->lin->nparts!=2 || b->lin->nparts!=2 || !fixture_same_vector(a->b,b->b))ok=0;
    for(size_t part=0;part<2;part++) {
      if(a->lin->off[part]!=offsets[idx[part]] || b->lin->off[part]!=offsets[idx[part]]
         || !fixture_same_vector(a->lin->phi[part],b->lin->phi[part]))ok=0;
    }
    if(a->quad->len!=b->quad->len)ok=0;
    for(size_t part=0;part<a->quad->len;part++) {
      if(a->quad->rows[part]!=b->quad->rows[part] || a->quad->cols[part]!=b->quad->cols[part])ok=0;
      for(size_t k=0;k<K;k++)if(memcmp(a->quad->coeffs[part]->proj[k],b->quad->coeffs[part]->proj[k],sizeof(poly)))ok=0;
    }
  }
  /* Output checks own a deep copy; releasing their temporary source must not
   * invalidate linear, quadratic or constant coefficients. */
  sparsecnst borrowed, copied;
  struct _sparsecnst *source=st[0]->zqcnst->sparse[0];
  sparsecnst_borrow_public(borrowed,source);
  if(borrowed->b->alloc || !fixture_same_vector(borrowed->b,source->b))ok=0;
  for(size_t part=0;part<source->lin->nparts;part++) {
    if(borrowed->lin->phi[part]->alloc
       || !fixture_same_vector(borrowed->lin->phi[part],source->lin->phi[part]))ok=0;
    for(size_t k=0;k<K;k++)
      if(borrowed->lin->phi[part]->proj[k]!=source->lin->phi[part]->proj[k])ok=0;
    size_t original=source->lin->off[part];
    borrowed->lin->off[part]++;
    if(source->lin->off[part]!=original)ok=0;
    borrowed->lin->off[part]=original;
  }
  if(source->quad->len && borrowed->quad->rows==source->quad->rows)ok=0;
  /* A later transform may deep-copy a view. That copy must outlive both
   * the view and its source; freeing the view must leave its owner intact. */
  sparsecnst_copy2(copied,borrowed,borrowed->quad->len);
  sparsecnst_free(borrowed);
  if(!fixture_same_vector(source->b,st[1]->zqcnst->sparse[0]->b))ok=0;
  py_free_statement(st[0]);
  struct _sparsecnst *expected=st[1]->zqcnst->sparse[0];
  if(!fixture_same_vector(copied->b,expected->b))ok=0;
  for(size_t part=0;part<copied->lin->nparts;part++) {
    if(copied->lin->off[part]!=expected->lin->off[part]
       || !fixture_same_vector(copied->lin->phi[part],expected->lin->phi[part]))ok=0;
  }
  for(size_t part=0;part<copied->quad->len;part++) {
    if(copied->quad->rows[part]!=expected->quad->rows[part]
       || copied->quad->cols[part]!=expected->quad->cols[part])ok=0;
    for(size_t k=0;k<K;k++)if(memcmp(copied->quad->coeffs[part]->proj[k],expected->quad->coeffs[part]->proj[k],sizeof(poly)))ok=0;
  }
  sparsecnst_free(copied);
  py_free_statement(st[1]);
  return ok;
}

int quil_fixture_test_private_mask_range(void) {
  polz values[1];
  poly planes[32];
  int64_t coefficients[N]={0};
  for(unsigned int bits=1;bits<=32;bits++) {
    const int64_t limit=INT64_C(1)<<(bits-1);
    coefficients[0]=-limit;coefficients[N-1]=limit-1;
    polzvec_fromint64vec(values,1,1,coefficients);
    if(!quil_private_mask_fits(values,1,bits))return 0;
    polzvec_bindec(planes,values,1,1,bits);
    for(size_t j=0;j<N;j++) {
      int64_t reconstructed=0;
      for(unsigned int bit=0;bit<bits;bit++) {
        if(planes[bit]->c[j]!=0 && planes[bit]->c[j]!=1)return 0;
        int64_t weight=INT64_C(1)<<bit;
        reconstructed+=(bit+1==bits ? -weight : weight)*planes[bit]->c[j];
      }
      if(reconstructed!=coefficients[j])return 0;
    }
    coefficients[0]=-limit-1;
    polzvec_fromint64vec(values,1,1,coefficients);
    if(quil_private_mask_fits(values,1,bits))return 0;
    coefficients[0]=0;coefficients[N-1]=limit;
    polzvec_fromint64vec(values,1,1,coefficients);
    if(quil_private_mask_fits(values,1,bits))return 0;
    coefficients[N-1]=0;
  }
  return !quil_private_mask_fits(values,1,0) && !quil_private_mask_fits(values,1,33);
}

int quil_fixture_test_empty_optional_dachshund_parameters(void) {
  fixture_context *ctx=quil_fixture_new(2,1,0);
  int64_t zero[N]={0},coefficients[2*N]={0};
  size_t indices[2]={0,1};
  coefficients[0]=1;coefficients[N]=-1;
  if(!ctx)return 0;
  int ok=!quil_fixture_binary(ctx,zero) && !quil_fixture_binary(ctx,zero)
      && !quil_fixture_linear(ctx,2,indices,coefficients,zero,1);
  dch_params pp[2];
  size_t proof_bits[2],witness_bits[2];
  for(size_t i=0;i<2 && ok;i++) {
    memset(pp[i],i ? 0x5a : 0xa5,sizeof(pp[i]));
    if(dch_params_gen(pp[i],&proof_bits[i],&witness_bits[i],ctx->st,1)) {
      if(i)dch_params_free(pp[0]);
      quil_fixture_free(ctx);return 0;
    }
  }
  if(ok) {
    for(size_t i=0;i<2;i++) {
      if(pp[i]->nexact || pp[i]->nquad || pp[i]->len_exact_total
         || pp[i]->off_quad_left || pp[i]->off_quad_right)ok=0;
    }
    if(pp[0]->r!=pp[1]->r || proof_bits[0]!=proof_bits[1]
       || witness_bits[0]!=witness_bits[1])ok=0;
    for(size_t i=0;i<pp[0]->r && ok;i++) {
      if(pp[0]->n[i]!=pp[1]->n[i] || pp[0]->normsq[i]!=pp[1]->normsq[i]
         || pp[0]->normty[i]!=pp[1]->normty[i])ok=0;
    }
    dch_params_free(pp[0]);dch_params_free(pp[1]);
  }
  quil_fixture_free(ctx);
  return ok;
}

int quil_fixture_test_deferred_challenges(void) {
  const size_t lengths[]={0,1,31,32,33,257,4097};
  int ok=1;
  for(size_t test=0;test<sizeof(lengths)/sizeof(lengths[0]);test++) {
    size_t length=lengths[test];
    polxvec serial[4],deferred[4];quil_zq_job jobs[4];
    pthread_t threads[4];int started[4]={0};
    uint8_t sh[HASHLEN],dh[HASHLEN];
    for(size_t j=0;j<HASHLEN;j++)sh[j]=dh[j]=(uint8_t)(j*17+test);
    for(size_t i=0;i<4;i++) {
      int64_t scalars[37],other[37];
      sample_chalz(scalars,37,sh);sample_chalz(other,37,dh);
      if(memcmp(scalars,other,sizeof(scalars)))ok=0;
      memset(serial[i],0,sizeof(polxvec));memset(deferred[i],0,sizeof(polxvec));
      if(length) {
        polxvec_init(serial[i],length,1);polxvec_init(deferred[i],length,1);
        sample_chalx_uniform(serial[i],sh);
      }
      jobs[i]=(quil_zq_job){.chalx=deferred[i]};
      quil_zq_prepare_challenge_seed(&jobs[i],dh);
      if(memcmp(sh,dh,HASHLEN))ok=0;
    }
    // Expand all four only after the interleaved transcript updates finish.
    for(size_t i=1;i<4;i++) {
      if(!pthread_create(&threads[i],NULL,quil_zq_expand_challenges,&jobs[i]))started[i]=1;
      else quil_zq_expand_challenges(&jobs[i]);
    }
    quil_zq_expand_challenges(&jobs[0]);
    for(size_t i=1;i<4;i++)if(started[i] && pthread_join(threads[i],NULL))abort();
    for(size_t i=0;i<4;i++)if(length) {
      if(!fixture_same_vector(serial[i],deferred[i]))ok=0;
      polxvec_free(serial[i]);polxvec_free(deferred[i]);
    }
  }
  return ok;
}

int quil_fixture_test_parallel_zq(void) {
  fixture_context *ctx=quil_fixture_new(2,0,64);
  if(!ctx)return 0;
  int64_t zero[N]={0},coefficients[2*N]={0};
  size_t indices[2]={0,1};
  coefficients[0]=1;coefficients[N]=-1;
  int ok=!quil_fixture_binary(ctx,zero) && !quil_fixture_binary(ctx,zero);
  for(size_t i=0;i<64;i++) {
    // Mixed zero/nonzero public RHS values exercise the worker shortcut and
    // ordinary accumulation. This diagnostic compares aggregation, not witnesses.
    zero[0]=(int64_t)(i%3)-1;
    if(quil_fixture_linear(ctx,2,indices,coefficients,zero,0))ok=0;
  }
  zero[0]=0;
  sparsecnst serial[4],parallel[4];
  polxvec chalx[4];int64_t chalz[4][64];quil_zq_job jobs[4];
  for(size_t i=0;i<4;i++) {
    for(size_t j=0;j<64;j++)chalz[i][j]=((int64_t)1<<(LOGQ-1))-1-(int64_t)(i*64+j);
    if(i&1)for(size_t j=0;j<64;j++)chalz[i][j]=-chalz[i][j];
    memset(chalx[i],0,sizeof(polxvec));
    size_t nx=ctx->st->zqcnst->sigmam1_nchal;
    if(nx){uint8_t seed[SEEDLEN]={0};seed[0]=i;polxvec_init(chalx[i],nx,1);polxvec_almostuniform(chalx[i],seed,0);}
    for(size_t mode=0;mode<2;mode++) {
      struct _sparsecnst *out=mode ? parallel[i] : serial[i];
      sparsecnst_init(out,1);quadfunc_init(out->quad,0,3);
      linfunc_init(out->lin,1,1,1);out->lin->off[0]=0;
      polxvec_init(out->lin->phi[0],2,1);polxvec_setzero(out->lin->phi[0],0,1,2);
    }
    zqcnstset_aggregate_add(serial[i],ctx->st->zqcnst,chalz[i],chalx[i]);
    sparsecnst_refresh(serial[i]);
    jobs[i]=(quil_zq_job){.out=parallel[i],.input=ctx->st->zqcnst,
                         .chalz=chalz[i],.chalx=chalx[i]};
    // Regenerate the same challenges in the actual aggregation worker after
    // the serial reference has consumed them; poison the old buffer first.
    if(nx) {
      jobs[i].expand_chalx=1;jobs[i].chalx_seed[0]=(uint8_t)i;
      polxvec_setzero(chalx[i],0,1,nx);
    }
  }
  quil_zq_execute_batch(jobs,4);
  for(size_t i=0;i<4;i++) {
    if(!fixture_same_vector(serial[i]->b,parallel[i]->b)
       || !fixture_same_vector(serial[i]->lin->phi[0],parallel[i]->lin->phi[0])
       || serial[i]->quad->len!=parallel[i]->quad->len)ok=0;
    for(size_t j=0;j<serial[i]->quad->len;j++) {
      if(serial[i]->quad->rows[j]!=parallel[i]->quad->rows[j]
         || serial[i]->quad->cols[j]!=parallel[i]->quad->cols[j]
         || memcmp(serial[i]->quad->coeffs[j],parallel[i]->quad->coeffs[j],sizeof(polx)))ok=0;
    }
    sparsecnst_free(serial[i]);sparsecnst_free(parallel[i]);
    if(chalx[i]->alloc)polxvec_free(chalx[i]);
  }
  if(quil_zq_batch_size(0,0)!=1 || quil_zq_batch_size(SIZE_MAX,SIZE_MAX)!=1)ok=0;
  quil_fixture_free(ctx);return ok;
}

int quil_fixture_test_parallel_jl(void) {
  const size_t lengths[]={17,257,1025};
  int ok=1;
  for(size_t test=0;test<sizeof(lengths)/sizeof(lengths[0]);test++) {
    size_t nmax=lengths[test],bits=31,bytes=2*nmax*256*N/8;
    uint8_t initial[HASHLEN],serial_h[HASHLEN],parallel_h[HASHLEN],*input1,*input2;
    for(size_t i=0;i<HASHLEN;i++)initial[i]=(uint8_t)(7*i+3);
    jl_sample_mat(&input1,&input2,initial,nmax);
    uint8_t *original=malloc(bytes);
    if(!original){free(input1);return 0;}
    memcpy(original,input1,bytes);
    memcpy(serial_h,initial,HASHLEN);memcpy(parallel_h,initial,HASHLEN);
    polxvec serial_mat[LIFTS],serial_proj[LIFTS],parallel_mat[LIFTS],parallel_proj[LIFTS];
    // Original serial schedule, independent of the batch preparation helper.
    uint8_t hashbuf[64+QBYTES*256+24] __attribute__((aligned(64)));
    int64_t challenge[256] __attribute__((aligned(64)));
    for(size_t i=0;i<LIFTS;i++) {
      shake128(hashbuf,sizeof(hashbuf),serial_h,HASHLEN);
      memcpy(serial_h,hashbuf,HASHLEN);
      jlproj_expand_challenge(challenge,&hashbuf[64]);
      polxvec_init(serial_mat[i],nmax,1);polxvec_init(serial_proj[i],bits,1);
      jl_aggregate_mat(serial_mat[i],input1,input2,challenge);
      jl_aggregate_proj(serial_proj[i],bits,challenge);
    }
    quil_collapse_jl(parallel_mat,parallel_proj,nmax,bits,input1,input2,parallel_h);
    if(memcmp(serial_h,parallel_h,HASHLEN) || memcmp(original,input1,bytes))ok=0;
    for(size_t i=0;i<LIFTS;i++) {
      if(memcmp(serial_mat[i]->widths,parallel_mat[i]->widths,nmax*sizeof(double))
         || memcmp(serial_proj[i]->widths,parallel_proj[i]->widths,bits*sizeof(double)))ok=0;
      for(size_t k=0;k<K;k++) {
        if(memcmp(serial_mat[i]->proj[k],parallel_mat[i]->proj[k],nmax*sizeof(poly))
           || memcmp(serial_proj[i]->proj[k],parallel_proj[i]->proj[k],bits*sizeof(poly)))ok=0;
      }
      polxvec_free(serial_mat[i]);polxvec_free(serial_proj[i]);
      polxvec_free(parallel_mat[i]);polxvec_free(parallel_proj[i]);
    }
    free(original);free(input1);
  }
  if(quil_jl_batch_size(0)!=1 || quil_jl_batch_size(SIZE_MAX)!=1)ok=0;
  return ok;
}

static void fixture_rotation_values(polxvec out,size_t salt) {
  int64_t values[32*N];
  polxvec part;
  for(size_t off=0;off<out->len;off+=32) {
    size_t count=MIN(32,out->len-off);
    for(size_t i=0;i<count*N;i++) {
      uint64_t x=(off*N+i+salt)*UINT64_C(6364136223846793005);
      values[i]=(int64_t)(x&((UINT64_C(1)<<37)-1))-(INT64_C(1)<<36);
    }
    polxvec_init_subvec2(part,out,off,1,count);
    polxvec_fromint64vec(part,values,count,1,1e22);
  }
}
static int fixture_rotation_equal(const polxvec a,const polxvec b) {
  if(memcmp(a->widths,b->widths,a->len*sizeof(double)))return 0;
  for(size_t k=0;k<K;k++)
    if(memcmp(a->proj[k],b->proj[k],a->len*sizeof(poly)))return 0;
  return 1;
}
int quil_fixture_test_parallel_rotation(void) {
  int ok=1;
  const size_t ranks[]={1,3,8,17},lengths[]={31,257,1031};
  for(size_t ri=0;ri<4;ri++)for(size_t li=0;li<3;li++) {
    size_t rank=ranks[ri],length=lengths[li],degree=next2power(rank);
    size_t padded=(length/degree+(length%degree!=0))*degree,total=2*padded+11;
    polxvec serial,parallel,key,key_copy,challenge,challenge_copy;
    polxvec_init(serial,total,1);polxvec_init(parallel,total,1);
    polxvec_init(key,total,1);polxvec_init(key_copy,total,1);
    polxvec_init(challenge,rank,1);polxvec_init(challenge_copy,rank,1);
    fixture_rotation_values(serial,11);fixture_rotation_values(key,101);
    int64_t small[17*N];
    for(size_t i=0;i<rank*N;i++)small[i]=(int64_t)((i*13+7)%31)-15;
    polxvec_fromint64vec(challenge,small,rank,1,65536);
    polxvec_scale_add(serial,serial,19);
    polxvec_copy(parallel,serial);polxvec_copy(key_copy,key);
    polxvec_copy(challenge_copy,challenge);
    for(size_t stride=1;stride<=2;stride++) {
      polxvec a,b,k;
      polxvec_init_subvec2(a,serial,5,stride,length);
      polxvec_init_subvec2(b,parallel,5,stride,length);
      polxvec_init_subvec2(k,key,5,stride,padded);
      polxvec_rotation_aggregate_add(a,challenge,k);
      quil_polxvec_parallel_rotation_add(b,challenge,k);
      // Full allocation comparison covers untouched sentinels and widths.
      if(!fixture_rotation_equal(serial,parallel) ||
         !fixture_rotation_equal(key,key_copy) ||
         !fixture_rotation_equal(challenge,challenge_copy))ok=0;
    }
    polxvec_free(serial);polxvec_free(parallel);polxvec_free(key);
    polxvec_free(key_copy);polxvec_free(challenge);polxvec_free(challenge_copy);
  }
  return ok;
}

int quil_fixture_test_wide_crt(void) {
  const size_t lengths[]={1,31,32,33,65};
  int ok=1;
  for(size_t li=0;li<sizeof(lengths)/sizeof(lengths[0]);li++) {
    size_t length=lengths[li],total=2*length+11;
    polxvec input,original;
    polxvec_init(input,total,1);polxvec_init(original,total,1);
    polz *expected=_aligned_alloc(64,length*sizeof(polz));
    polz *actual=_aligned_alloc(64,length*sizeof(polz));
    for(size_t mode=0;mode<5;mode++) {
      if(mode==0)polxvec_setzero(input,0,1,total);
      else {
        fixture_rotation_values(input,1009+li);
        if(mode==2)polxvec_scale_add(input,input,65535);
      }
      if(mode==3) {
        const int64_t q=(INT64_C(1)<<LOGQ)-QOFF;
        const int64_t edges[]={0,1,-1,q/2,-q/2,q/2+1,-q/2-1,q-1,q,q+1,-q+1,-q,-q-1,3*q};
        int64_t values[N];polxvec one;
        for(size_t i=0;i<total;i++) {
          for(size_t c=0;c<N;c++)values[c]=edges[(c+i)%(sizeof(edges)/sizeof(edges[0]))];
          polxvec_init_subvec2(one,input,i,1,1);
          polxvec_fromint64vec(one,values,1,1,1e24);
        }
      }
      if(mode==4) {
        uint32_t state=0x28197ab5U;
        // Exercise each projection independently within its NTT input range.
        for(size_t p=0;p<K;p++)for(size_t i=0;i<total;i++)for(size_t c=0;c<N;c++) {
          state=state*1664525U+1013904223U;
          input->proj[p][i]->c[c]=(int16_t)((int32_t)(state%(2U*(uint32_t)primes[p]->p+1U))-primes[p]->p);
        }
      }
      polxvec_copy(original,input);
      for(ssize_t stride=-1;stride<=2;stride++)if(stride) {
        size_t off=stride<0 ? total-6 : 5;
        for(size_t i=0;i<length;i++) {
          size_t index=(size_t)((ssize_t)off+(ssize_t)i*stride);
          polx single;
          single->width=input->widths[index];
          for(size_t p=0;p<K;p++)memcpy(single->proj[p],input->proj[p][index],sizeof(poly));
          // Independent retained scalar CRT path uses original limb arithmetic.
          polz_frompolx(expected[i],single);
        }
        polzvec_frompolxvec(actual,input,off,stride,length);
        if(memcmp(expected,actual,length*sizeof(polz)))ok=0;
        polzvec_center(expected,length);polzvec_center(actual,length);
        if(memcmp(expected,actual,length*sizeof(polz)))ok=0;
        if(!fixture_same_vector(input,original))ok=0;
      }
    }
    free(expected);free(actual);polxvec_free(input);polxvec_free(original);
  }
  return ok;
}

int quil_fixture_test_public_refresh(void) {
  int ok=1;
  const size_t lengths[]={31,32,33,127,1031};
  for(size_t li=0;li<sizeof(lengths)/sizeof(lengths[0]);li++) {
    size_t length=lengths[li],total=2*length+11;
    for(size_t mode=0;mode<3;mode++)for(size_t stride=1;stride<=2;stride++) {
      polxvec serial,optimized,a,b;
      polxvec_init(serial,total,1);polxvec_init(optimized,total,1);
      polxvec_setzero(serial,0,1,total);
      // Zero values with noncanonical widths still need a canonical width.
      polxvec_setwidths1(serial,0,1,total,1234567);
      polxvec_monomial(serial,0,0,19);polxvec_monomial(serial,total-1,3,-17);
      if(mode==1) {
        polxvec_monomial(serial,5+stride*(length/2),7,-9);
        polxvec_monomial(serial,5+stride*(length-1),255,13);
      }
      if(mode==2) {
        // A nonzero value only in the last CRT projection must not be skipped.
        serial->proj[K-1][5+stride*(length/2)]->c[17]=1;
      }
      polxvec_copy(optimized,serial);
      polxvec_init_subvec2(a,serial,5,stride,length);
      polxvec_init_subvec2(b,optimized,5,stride,length);
      polxvec_refresh(a);quil_public_polxvec_refresh(b);
      if(!fixture_same_vector(serial,optimized))ok=0;
      polxvec_free(serial);polxvec_free(optimized);
    }
  }
  return ok;
}

int quil_fixture_test_parallel_refresh(void) {
  const size_t length=16391,total=2*length+11;
  polxvec serial,parallel,part;
  polxvec_init(serial,total,1);polxvec_init(parallel,total,1);
  int64_t values[32*N];
  for(size_t offset=0;offset<total;offset+=32) {
    size_t count=MIN(32,total-offset);
    for(size_t i=0;i<count*N;i++) {
      uint64_t x=(offset*N+i)*UINT64_C(6364136223846793005)+UINT64_C(1442695040888963407);
      values[i]=(int64_t)(x&((UINT64_C(1)<<37)-1))-(INT64_C(1)<<36);
    }
    polxvec_init_subvec2(part,serial,offset,1,count);
    polxvec_fromint64vec(part,values,count,1,1e22);
  }
  // Nonstandard widths and unreduced values must match after refresh too.
  polxvec_scale_add(serial,serial,19);
  polxvec_copy(parallel,serial);
  int ok=1;
  for(size_t stride=1;stride<=2;stride++) {
    polxvec a,b;
    polxvec_init_subvec2(a,serial,5,stride,length);
    polxvec_init_subvec2(b,parallel,5,stride,length);
    polxvec_refresh(a);
    quil_polxvec_parallel_refresh(b);
    // Compare the whole backing allocation, including untouched sentinels.
    if(memcmp(serial->widths,parallel->widths,total*sizeof(double)))ok=0;
    for(size_t k=0;k<K;k++)
      if(memcmp(serial->proj[k],parallel->proj[k],total*sizeof(poly)))ok=0;
  }
  polxvec_free(serial);polxvec_free(parallel);
  return ok;
}

static void fixture_random_polxvec(polxvec out,size_t salt) {
  int64_t values[32*N];
  polxvec part;
  for(size_t off=0;off<out->len;off+=32) {
    size_t count=MIN(32,out->len-off);
    for(size_t i=0;i<count*N;i++) {
      uint64_t x=(off*N+i+salt)*UINT64_C(6364136223846793005)+UINT64_C(1442695040888963407);
      values[i]=(int64_t)(x&((UINT64_C(1)<<37)-1))-(INT64_C(1)<<36);
    }
    polxvec_init_subvec2(part,out,off,1,count);
    polxvec_fromint64vec(part,values,count,1,1e22);
  }
}

/* Refresh is idempotent: a second refresh of a canonical vector reproduces the
 * same limbs and widths. The LNP verifier check relies on this to omit
 * whole-constraint refreshes of components that were refreshed individually. */
int quil_fixture_test_refresh_idempotent(void) {
  const size_t lengths[]={1,31,32,33,1025};
  int ok=1;
  for(size_t li=0;li<sizeof(lengths)/sizeof(lengths[0]);li++) {
    size_t length=lengths[li];
    polxvec once,twice;
    polxvec_init(once,length,1);polxvec_init(twice,length,1);
    fixture_random_polxvec(once,li);
    // Unreduced values with nonstandard widths, including zero and monomials.
    polxvec_scale_add(once,once,23);
    polxvec_monomial(once,0,0,0);
    if(length>2)polxvec_monomial(once,2,5,-7);
    polxvec_refresh(once);
    polxvec_copy(twice,once);
    polxvec_refresh(twice);
    if(!fixture_same_vector(once,twice))ok=0;
    polxvec_free(once);polxvec_free(twice);
  }
  return ok;
}

/* The batched LNP collapse must reproduce the serial jl_aggregate_mat outputs
 * for more jobs than the thread limit, leaving inputs untouched. */
int quil_fixture_test_parallel_jl_mat(void) {
  const size_t total=1+LNP_NPROJ,nmax=257;
  size_t bytes=2*nmax*256*N/8;
  uint8_t h[HASHLEN],*input1,*input2;
  int ok=1;
  for(size_t i=0;i<HASHLEN;i++)h[i]=(uint8_t)(5*i+1);
  jl_sample_mat(&input1,&input2,h,nmax);
  uint8_t *original=malloc(bytes);
  if(!original){free(input1);return 0;}
  memcpy(original,input1,bytes);
  int64_t *chalz[total];
  polxvec serial[total],parallel[total];
  quil_jl_mat_job jobs[total];
  for(size_t j=0;j<total;j++) {
    chalz[j]=_malloc(256*sizeof(int64_t));
    sample_chalz(chalz[j],256,h);
    polxvec_init(serial[j],nmax-j,1);polxvec_init(parallel[j],nmax-j,1);
    jl_aggregate_mat(serial[j],input1,input2,chalz[j]);
    jobs[j]=(quil_jl_mat_job){.out=parallel[j],.jlmat1=input1,.jlmat2=input2,.chalz=chalz[j]};
  }
  quil_jl_mat_execute_all(jobs,total);
  if(memcmp(original,input1,bytes))ok=0;
  for(size_t j=0;j<total;j++) {
    if(!fixture_same_vector(serial[j],parallel[j]))ok=0;
    polxvec_free(serial[j]);polxvec_free(parallel[j]);free(chalz[j]);
  }
  free(original);free(input1);
  return ok;
}

static void fixture_ldr_zq_serial(sparsecnst zqagg[LIFTS],const statement ist,
                                  const uint8_t *jlmat1,const uint8_t *jlmat2,
                                  const int32_t p[256],size_t nn,size_t r_old,
                                  uint8_t h[HASHLEN]) {
  // The original (pre-batching) normal-round schedule, kept as the reference.
  size_t i,nchalz,nchalx;
  int64_t *chalz,proj;
  polxvec chalx;
  __attribute__((aligned(64)))
  uint8_t hashbuf[64+QBYTES*256+24];
  nchalz=ist->zqcnst->sparse_nchal+ist->zqcnst->int_nchal;
  nchalx=ist->zqcnst->sigmam1_nchal;
  chalz=_aligned_alloc(64,(256+nchalz+64-nchalz%64)*sizeof(int64_t));
  memset(chalx,0,sizeof(polxvec));
  if(nchalx>0)polxvec_init(chalx,nchalx,1);
  for(i=0;i<LIFTS;i++) {
    shake128(hashbuf,sizeof(hashbuf),h,HASHLEN);
    memcpy(h,hashbuf,HASHLEN);
    jlproj_expand_challenge(chalz,&hashbuf[64]);
    sample_chalz(&chalz[256],nchalz,h);
    if(nchalx>0)sample_chalx_uniform(chalx,h);
    sparsecnst_init(zqagg[i],1);
    quadfunc_init(zqagg[i]->quad,0,(r_old*r_old+r_old)/2);
    linfunc_init(zqagg[i]->lin,1,1,1);
    zqagg[i]->lin->off[0]=0;
    polxvec_init(zqagg[i]->lin->phi[0],nn,1);
    jl_aggregate_mat(zqagg[i]->lin->phi[0],jlmat1,jlmat2,chalz);
    proj=jlproj_collapsproj(p,chalz);
    polxvec_monomial(zqagg[i]->b,0,0,proj);
    zqcnstset_aggregate_add(zqagg[i],ist->zqcnst,&chalz[256],chalx);
    sparsecnst_refresh(zqagg[i]);
    zqagg[i]->quad->coeffs=realloc(zqagg[i]->quad->coeffs,zqagg[i]->quad->len*sizeof(polx));
  }
  free(chalz);
  if(nchalx>0)polxvec_free(chalx);
}

static int fixture_same_sparsecnst(const sparsecnst a,const sparsecnst b) {
  if(!fixture_same_vector(a->b,b->b) || !fixture_same_vector(a->lin->phi[0],b->lin->phi[0])
     || a->quad->len!=b->quad->len)return 0;
  for(size_t j=0;j<a->quad->len;j++) {
    if(a->quad->rows[j]!=b->quad->rows[j] || a->quad->cols[j]!=b->quad->cols[j]
       || memcmp(a->quad->coeffs[j],b->quad->coeffs[j],sizeof(polx)))return 0;
  }
  return 1;
}

/* The batched normal-round Zq aggregation must reproduce the original serial
 * schedule: same transcript state, values, widths and quadratic terms, with
 * the JL inputs untouched. Exercised through the real ldr_aggregate_zq (whose
 * batch size follows the witness length) and through a forced four-way batch. */
int quil_fixture_test_parallel_ldr_zq(void) {
  const size_t nn=300,r_old=2,bytes=2*nn*256*N/8;
  fixture_context *ctx=quil_fixture_new(nn,0,64);
  if(!ctx)return 0;
  int64_t zero[N]={0},coefficients[2*N]={0};
  size_t indices[2]={0,1};
  coefficients[0]=1;coefficients[N]=-1;
  int ok=1;
  for(size_t i=0;i<nn;i++)if(quil_fixture_binary(ctx,zero))ok=0;
  for(size_t i=0;i<64;i++) {
    zero[0]=(int64_t)(i%3)-1;
    if(quil_fixture_linear(ctx,2,indices,coefficients,zero,0))ok=0;
  }
  if(!ok){quil_fixture_free(ctx);return 0;}
  uint8_t initial[HASHLEN],serial_h[HASHLEN],parallel_h[HASHLEN],*jlmat1,*jlmat2;
  int32_t p[256];
  for(size_t i=0;i<HASHLEN;i++)initial[i]=(uint8_t)(11*i+2);
  for(size_t i=0;i<256;i++)p[i]=(int32_t)((i*7919)%4001)-2000;
  memcpy(serial_h,initial,HASHLEN);
  jl_sample_mat(&jlmat1,&jlmat2,serial_h,nn);
  memcpy(parallel_h,serial_h,HASHLEN);
  uint8_t *original=malloc(bytes);
  if(!original){free(jlmat1);quil_fixture_free(ctx);return 0;}
  memcpy(original,jlmat1,bytes);
  sparsecnst serial[LIFTS],parallel[LIFTS];
  fixture_ldr_zq_serial(serial,ctx->st,jlmat1,jlmat2,p,nn,r_old,serial_h);
  ldr_aggregate_zq(parallel,ctx->st,jlmat1,jlmat2,p,nn,r_old,parallel_h);
  if(memcmp(serial_h,parallel_h,HASHLEN) || memcmp(original,jlmat1,bytes))ok=0;
  for(size_t i=0;i<LIFTS;i++) {
    if(!fixture_same_sparsecnst(serial[i],parallel[i]))ok=0;
    sparsecnst_free(parallel[i]);
  }
  // Forced four-way batch against the same serial reference.
  {
    size_t nchalz=ctx->st->zqcnst->sparse_nchal+ctx->st->zqcnst->int_nchal;
    size_t nchalx=ctx->st->zqcnst->sigmam1_nchal;
    size_t chalz_len=256+nchalz+64-nchalz%64;
    int64_t *chalz[LIFTS];
    polxvec chalx[LIFTS];
    quil_ldr_zq_job jobs[LIFTS];
    __attribute__((aligned(64)))
    uint8_t hashbuf[64+QBYTES*256+24];
    memcpy(parallel_h,initial,HASHLEN);
    free(jlmat1);
    jl_sample_mat(&jlmat1,&jlmat2,parallel_h,nn);
    for(size_t i=0;i<LIFTS;i++) {
      chalz[i]=_aligned_alloc(64,chalz_len*sizeof(int64_t));
      memset(chalx[i],0,sizeof(polxvec));
      if(nchalx>0)polxvec_init(chalx[i],nchalx,1);
      shake128(hashbuf,sizeof(hashbuf),parallel_h,HASHLEN);
      memcpy(parallel_h,hashbuf,HASHLEN);
      jlproj_expand_challenge(chalz[i],&hashbuf[64]);
      sample_chalz(&chalz[i][256],nchalz,parallel_h);
      sparsecnst_init(parallel[i],1);
      quadfunc_init(parallel[i]->quad,0,(r_old*r_old+r_old)/2);
      linfunc_init(parallel[i]->lin,1,1,1);
      parallel[i]->lin->off[0]=0;
      polxvec_init(parallel[i]->lin->phi[0],nn,1);
      jobs[i]=(quil_ldr_zq_job){.out=parallel[i],.input=ctx->st->zqcnst,
                                .jlmat1=jlmat1,.jlmat2=jlmat2,.p=p,
                                .chalz=chalz[i],.chalx=chalx[i]};
      quil_ldr_zq_prepare_challenge_seed(&jobs[i],parallel_h);
    }
    quil_ldr_zq_execute_batch(jobs,LIFTS);
    if(memcmp(serial_h,parallel_h,HASHLEN) || memcmp(original,jlmat1,bytes))ok=0;
    for(size_t i=0;i<LIFTS;i++) {
      parallel[i]->quad->coeffs=realloc(parallel[i]->quad->coeffs,parallel[i]->quad->len*sizeof(polx));
      if(!fixture_same_sparsecnst(serial[i],parallel[i]))ok=0;
      sparsecnst_free(parallel[i]);sparsecnst_free(serial[i]);
      free(chalz[i]);
      if(nchalx>0)polxvec_free(chalx[i]);
    }
  }
  if(quil_ldr_zq_batch_size(0)!=1 || quil_ldr_zq_batch_size(SIZE_MAX)!=1)ok=0;
  free(original);free(jlmat1);
  quil_fixture_free(ctx);
  return ok;
}

/* Sliced mul-add plus refresh must match the serial call for inputs that do
 * and do not trigger the width-overflow pre-refresh, leaving inputs intact. */
int quil_fixture_test_parallel_mul_add_refresh(void) {
  const size_t lengths[]={255,256,257,1031};
  int ok=1;
  for(size_t li=0;li<sizeof(lengths)/sizeof(lengths[0]);li++)for(size_t mode=0;mode<2;mode++) {
    size_t length=lengths[li];
    polxvec serial,parallel,in,in_copy,scalar;
    polxvec_init(serial,length,1);polxvec_init(parallel,length,1);
    polxvec_init(in,length,1);polxvec_init(in_copy,length,1);polxvec_init(scalar,1,1);
    fixture_random_polxvec(serial,li+7);fixture_random_polxvec(in,li+29);
    fixture_random_polxvec(scalar,li+31);
    polxvec_refresh(in);polxvec_refresh(scalar);
    if(mode==1) {
      // Wide accumulated widths force the overflow pre-refresh path.
      polxvec_scale_add(serial,serial,((int64_t)1<<30));
      polxvec_setwidths1(serial,0,1,length,MAXWIDTH/2);
    } else polxvec_refresh(serial);
    polxvec_copy(parallel,serial);polxvec_copy(in_copy,in);
    polxvec_mul_add(serial,scalar,in);polxvec_refresh(serial);
    quil_polxvec_parallel_mul_add_refresh(parallel,scalar,in);
    if(!fixture_same_vector(serial,parallel) || !fixture_same_vector(in,in_copy))ok=0;
    polxvec_free(serial);polxvec_free(parallel);polxvec_free(in);polxvec_free(in_copy);polxvec_free(scalar);
  }
  return ok;
}

int quil_fixture_test_linear_only_rq_aggregation(void) {
  fixture_context *ctx=quil_fixture_new(2,1,0);
  int64_t zero[N]={0},coefficients[2*N]={0};
  size_t indices[2]={0,1};
  coefficients[0]=1;coefficients[N]=-1;
  if(!ctx)return 0;
  int ok=!quil_fixture_binary(ctx,zero) && !quil_fixture_binary(ctx,zero)
      && !quil_fixture_linear(ctx,2,indices,coefficients,zero,1);
  sparsecnst out;
  sparsecnst_init(out,1);quadfunc_init(out->quad,0,0);
  linfunc_init(out->lin,1,1,1);out->lin->off[0]=0;
  polxvec_init(out->lin->phi[0],2,1);
  polxvec_setzero(out->lin->phi[0],0,1,2);
  polxvec chal;polxvec_init(chal,1,1);polxvec_monomial(chal,0,0,1);
  if(ok)rqcnstset_aggregate_add(out,ctx->st->rqcnst,chal);
  rqcnstset empty;rqcnstset_init(empty,0,0);
  polxvec no_challenges={0};
  rqcnstset_aggregate_add(out,empty,no_challenges);
  polz centered[2];
  polzvec_frompolxvec(centered,out->lin->phi[0],0,1,2);
  polzvec_center(centered,2);
  for(size_t i=0;i<2;i++)for(size_t j=0;j<N;j++) {
    zz coefficient;polz_getcoeff(coefficient,centered[i],j);
    if(int64_fromzz(coefficient)!=coefficients[i*N+j])ok=0;
  }
  if(!polxvec_iszero(out->b))ok=0;
  rqcnstset_free(empty);polxvec_free(chal);sparsecnst_free(out);quil_fixture_free(ctx);
  return ok;
}

/* Exercise every fixed cache key against the ordinary native conversion,
 * plus general coefficients and a forced lookup-hash collision. */
static int fixture_test_conversion_cache(void) {
  fixture_coefficient_pool pool={0};
  const size_t count=FIXTURE_POOL_SLOTS+2;
  struct polxvec_str *owners=calloc(count,sizeof(*owners));
  if(!owners)abort();
  polxvec copied;
  polxvec_init(copied,1,1);
  int ok=1;
  for(size_t slot=0;slot<count;slot++) {
    int64_t raw[N]={0};
    if(slot>0 && slot<=2*N)raw[(slot-1)/2]=(slot&1) ? 1 : -1;
    else if(slot==2*N+1 || slot==2*N+2)
      for(size_t j=0;j<N;j++)raw[j]=slot==2*N+1 ? 1 : -1;
    else if(slot>=FIXTURE_POOL_SLOTS) {
      raw[0]=slot==FIXTURE_POOL_SLOTS ? 2 : -3;raw[N-1]=7;
    }
    if(fixture_pool_copy_cached(&pool,copied,raw))ok=0;
    polxvec_init(&owners[slot],1,1);
    polz lifted[1];
    polzvec_fromint64vec(lifted,1,1,raw);
    polzvec_topolxvec(&owners[slot],lifted,0,1,1);
    polxvec_setwidths1(&owners[slot],0,1,1,ldexp(1,2*LOGQ));
    fixture_pool_share(&pool,&owners[slot],raw);
    if(!fixture_pool_copy_cached(&pool,copied,raw)
       || !fixture_same_vector(copied,&owners[slot]))ok=0;
    if(slot==FIXTURE_POOL_SLOTS) {
      // Equal index/hash is insufficient when the original coefficients differ.
      pool.general[0].coefficients[0]++;
      if(fixture_pool_copy_cached(&pool,copied,raw))ok=0;
      pool.general[0].coefficients[0]--;
    }
  }
  if(pool.conversion_hits!=count)ok=0;
  fixture_pool_detach(&pool);
  for(size_t i=0;i<count;i++)polxvec_free(&owners[i]);
  fixture_pool_free(&pool);polxvec_free(copied);free(owners);
  return ok;
}

int quil_fixture_test_coefficient_pool(void) {
  fixture_context *shared=quil_fixture_new(2,5,0),*plain=quil_fixture_new(2,5,0);
  int64_t zero[N]={0},coeffs[2*N]={0};
  size_t indices[2]={0,1},lengths[2]={1,1};
  coeffs[0]=1;coeffs[N]=-1;
  int ok=shared && plain;
  if(!fixture_test_conversion_cache())ok=0;
  if(!ok)abort();
  for(size_t i=0;i<2;i++) {
    if(quil_fixture_binary(shared,zero) || quil_fixture_binary(plain,zero))ok=0;
  }
  for(size_t row=0;row<5;row++) {
    if(row==2)coeffs[0]=2;
    if(row==4)coeffs[0]=3;
    if(quil_fixture_linear(shared,2,indices,coeffs,zero,1))ok=0;
    if(py_append_constraint(plain->st,2,indices,lengths,1,coeffs,zero,1))ok=0;
  }
  if(shared->coefficients.conversion_hits!=10 || plain->coefficients.conversion_hits)ok=0;
  if(memcmp(shared->st->h,plain->st->h,HASHLEN))ok=0;
  if(quil_fixture_check(shared)!=1 || py_simple_verify(plain->st,plain->wt)!=1)ok=0;
  // Independently run the original general conversion for a zero RHS. Both
  // submitted contexts above use the optimized frontend, so comparing only
  // those two contexts would not check the zero-transform shortcut.
  polz zero_lift[1];
  polxvec zero_reference;
  polxvec_init(zero_reference,1,1);
  polzvec_fromint64vec(zero_lift,1,1,zero);
  polzvec_topolxvec(zero_reference,zero_lift,0,1,1);
  polxvec_setwidths1(zero_reference,0,1,1,ldexp(1,2*LOGQ));
  for(size_t row=0;row<5;row++) {
    struct _sparsecnst *a=shared->st->rqcnst->sparse[row],*b=plain->st->rqcnst->sparse[row];
    if(!fixture_same_vector(a->b,zero_reference))ok=0;
    if(!fixture_same_vector(a->b,b->b))ok=0;
    for(size_t part=0;part<2;part++)if(!fixture_same_vector(a->lin->phi[part],b->lin->phi[part]))ok=0;
  }
  fixture_context *zero_ctx=quil_fixture_new(2,1,0);
  if(!zero_ctx)abort();
  if(quil_fixture_binary(zero_ctx,zero) || quil_fixture_binary(zero_ctx,zero))ok=0;
  int64_t zero_terms[2*N]={0};
  if(quil_fixture_linear(zero_ctx,2,indices,zero_terms,zero,1))ok=0;
  struct _sparsecnst *zero_row=zero_ctx->st->rqcnst->sparse[0];
  for(size_t part=0;part<2;part++)
    if(!fixture_same_vector(zero_row->lin->phi[part],zero_reference))ok=0;
  quil_fixture_free(zero_ctx);
  polxvec_free(zero_reference);
  struct _sparsecnst *first=shared->st->rqcnst->sparse[0],*second=shared->st->rqcnst->sparse[1];
  if(first->lin->phi[0]->proj[0]!=second->lin->phi[0]->proj[0] || first->b->proj[0]!=second->b->proj[0])ok=0;
  if(shared->coefficients.count!=15 || shared->coefficients.general_count!=2 || plain->coefficients.count)ok=0;
  if(shared->st->rqcnst->sparse[2]->lin->phi[0]->proj[0]==first->lin->phi[0]->proj[0])ok=0;
  if(shared->st->rqcnst->sparse[2]->lin->phi[0]->proj[0]!=shared->st->rqcnst->sparse[3]->lin->phi[0]->proj[0])ok=0;
  if(shared->st->rqcnst->sparse[2]->lin->phi[0]->proj[0]==shared->st->rqcnst->sparse[4]->lin->phi[0]->proj[0])ok=0;
  // Releasing both shared and ordinary vectors exercises the ownership split.
  quil_fixture_free(shared);quil_fixture_free(plain);
  for(size_t i=0;i<N;i++) {
    memset(zero,0,sizeof(zero));zero[i]=1;
    if(fixture_coefficient_slot(zero)!=1+2*i)ok=0;
    zero[i]=-1;if(fixture_coefficient_slot(zero)!=2+2*i)ok=0;
  }
  for(size_t i=0;i<N;i++)zero[i]=1;
  if(fixture_coefficient_slot(zero)!=2*N+1)ok=0;
  for(size_t i=0;i<N;i++)zero[i]=-1;
  if(fixture_coefficient_slot(zero)!=2*N+2)ok=0;
  return ok;
}

/* Bounded public-fixture entry points for independent stream/sampler vectors. */
int quil_fixture_private_stream(const uint8_t seed[32],uint64_t nonce,size_t blocks,uint8_t *out) {
  if(!seed || !out || !blocks || blocks>8)return 1;
  aes256ctr_ctx state;
  aes256ctr_init(&state,seed,nonce);
  aes256ctr_squeezeblocks(out,blocks,&state);
  quil_prg_clear(&state,sizeof(state));
  return 0;
}
int quil_fixture_sample_prg(const uint8_t seed[32],uint64_t nonce,size_t count,
                            unsigned int scale,unsigned int mode,int64_t *out) {
  if(!seed || !out || !count || count>8 || scale>26 || mode>4)return 1;
  polz values[8];
  switch(mode) {
    case 0: polzvec_uniform(values,count,seed,nonce);break;
    case 1: quil_polzvec_uniform_private(values,count,seed,nonce);break;
    case 2: polzvec_gaussian(values,count,scale,seed,nonce);break;
    case 3: {
      // Historical AES-256 Gaussian reference, separate from private proving.
      int32_t coefficients[8*N];
      aes256ctr_ctx state;aes256ctr_init(&state,seed,nonce);
      quil_prg_stream stream={&state,quil_prg_aes256_squeeze};
      int status=quil_gaussian_i32_stream(coefficients,count*N,&stream,scale);
      if(!status)for(size_t i=0;i<count;i++)for(size_t j=0;j<N;j++)
        polz_setcoeff_fromint64(values[i],coefficients[i*N+j],j);
      quil_prg_clear(coefficients,sizeof(coefficients));quil_prg_clear(&state,sizeof(state));
      if(status) { quil_prg_clear(values,sizeof(values));return 1; }
      break;
    }
    case 4: if(quil_polzvec_gaussian_private(values,count,scale,seed,nonce)) { quil_prg_clear(values,sizeof(values));return 1; }break;
  }
  for(size_t i=0;i<count;i++)for(size_t j=0;j<N;j++) {
    zz value;polz_getcoeff(value,values[i],j);
    out[i*N+j]=int64_fromzz(value);
  }
  quil_prg_clear(values,sizeof(values));
  return 0;
}
#include "rejection.h"
int quil_fixture_private_rejection(const uint8_t seed[32],uint64_t nonce,unsigned int kind,
                                   int64_t zv,int64_t vv,double variance,double repetition) {
  if(!seed || kind>2 || vv<0 || !(variance>0) || !(repetition>0))return -1;
  aes256ctr_ctx state;
  aes256ctr_init(&state,seed,nonce);
  quil_prg_stream stream={&state,quil_prg_aes256_squeeze};
  int result;
  switch(kind) {
    case 0: result=quil_is_rejected_std0_stream(&stream,zv,vv,variance,repetition);break;
    case 1: result=quil_is_rejected_sgnleak0_stream(&stream,zv,vv,variance,repetition);break;
    default: result=quil_is_rejected_bimodal0_stream(&stream,zv,vv,variance,repetition);break;
  }
  quil_prg_clear(&state,sizeof(state));
  return result;
}

/* Exercise cleanup of partial proof states returned on sampling errors. */
int quil_fixture_test_partial_proof_cleanup(void) {
  lnp_params zk={0};
  pack_params params={0};
  params->np=3;params->zkp=&zk;
  for(unsigned int stage=0;stage<4;stage++) {
    dch_pack_proof proof={0};
    pack_proof_init(proof->pi_pack,params);
    if(stage>=1)proof->pi_pack->p[0]->m[0]=_aligned_alloc(64,sizeof(polz));
    if(stage>=2)proof->pi_pack->zkp[0]->m[0]=_aligned_alloc(64,sizeof(polz));
    if(stage>=3) {
      witness_init(proof->pi_pack->owt,1,1);
      proof->pi_pack->owt->n[0]=1;
      proof->pi_pack->owt->s[0]=_aligned_alloc(64,sizeof(poly));
    }
    fixture_decoded_free(proof);
  }
  return 1;
}

int quil_fixture_rejection_parts(double value,unsigned int mode,uint8_t out[16],int32_t *exponent,unsigned int *precision) {
  if(!precision || mode>2)return -1;
  *precision=LDBL_MANT_DIG;
  long double input=value;
  if(mode==1)input=1.0L+ldexpl(1.0L,1-LDBL_MANT_DIG);
  if(mode==2)input=ldexpl(1.0L,LDBL_MIN_EXP-LDBL_MANT_DIG);
  return quil_rejection_binary_parts(input,out,exponent);
}

int quil_fixture_exact_rejection(const uint8_t seed[32],uint64_t nonce,unsigned int kind,int64_t zv,int64_t vv,double standard_deviation,double repetition) {
  if(!seed)return -1;
  aes256ctr_ctx state;
  aes256ctr_init(&state,seed,nonce);
  quil_prg_stream stream={&state,quil_prg_aes256_squeeze};
  int result=quil_rejection_decide_sd_256_stream(&stream,kind,zv,vv,standard_deviation,repetition);
  quil_prg_clear(&state,sizeof(state));
  return result;
}

int quil_fixture_test_gaussian_limits(void) {
  uint8_t seed[32]={0};
  polz value[1];
  if(quil_polzvec_gaussian_private(value,1,27,seed,0)!=-1)return 0;
  if(quil_polzvec_gaussian_private(NULL,1,0,seed,0)!=-1)return 0;
  if(quil_polzvec_gaussian_private(value,SIZE_MAX,0,seed,0)!=-1)return 0;
  if(quil_polzvec_gaussian_private(NULL,0,0,seed,0)!=0)return 0;
  return 1;
}
