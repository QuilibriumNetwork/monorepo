#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include "proofsystem.h"
#include "polx.h"
#include "malloc.h"
#include "randombytes.h"
#include "aesctr.h"
#include "fips202.h"
#include "jlproj.h"
#include "comkey.h"

static int64_t cmodq(int64_t a) {
  int64_t t;
  const int64_t mask = ((int64_t)1 << LOGQ) - 1;
  const int64_t q = ((int64_t)1 << LOGQ) - QOFF;

  t = a >> LOGQ;
  a &= mask;
  a += t*QOFF;
  t = q/2 - a;
  a -= (t >> 63)&q;
  return a;
}

/*
  Initializes statement allocating space for up to maxr vectors
*/
void statement_init(statement st, size_t r, size_t maxr){
  st->r = r;
  st->n = _malloc(maxr*(sizeof(size_t) + 2*sizeof(uint64_t) + sizeof(normtype)));
  st->normsq = (uint64_t *) &st->n[maxr];
  st->normsq_req = &st->normsq[maxr];
  st->normty = (normtype *) &st->normsq_req[maxr];
  memset(st->normsq_req, 0, maxr*sizeof(uint64_t));
  rqcnstset_init(st->rqcnst, 0, 0);
  zqcnstset_init(st->zqcnst, 0, 0, 0, 0, 0);
#ifndef NDEBUG
  st->maxr = maxr;
#endif
}

void statement_free(statement st){
  free(st->n);
  rqcnstset_free(st->rqcnst);
  zqcnstset_free(st->zqcnst);
}

/*
  Initializes witness allocating space for up to maxr vectors
*/
void witness_init(witness wt, size_t r, size_t maxr){
  wt->r = r;
  wt->n = _malloc(maxr*(sizeof(size_t) + sizeof(poly*)));
  wt->s = (poly **) &wt->n[maxr];
#ifndef NDEBUG
  wt->maxr = maxr;
#endif
}

void witness_copy(witness out, const witness in){
  size_t i, nn;
  witness_init(out, in->r, in->r);
  nn = 0;
  for(i=0;i<out->r;i++){
    out->n[i] = in->n[i];
    nn += out->n[i];
  }
  out->s[0] = _aligned_alloc(64, nn*sizeof(poly));
  for(i=1;i<out->r;i++){
    out->s[i] = &out->s[i-1][out->n[i-1]];
  }
  polyvec_copy(out->s[0], in->s[0], 1, 1, nn);
}

void witness_free(witness wt){
  free(wt->s[0]);
  free(wt->n);
}

int sis_secure(size_t rank, double norm){
  double maxlog;

  double logdelta = LOGDELTA;
#ifdef QUIL_BENCH_KNOBS
  /* Benchmark-only: size the internal commitments at another root-Hermite
   * target (log2 delta) to measure the proof-size and time cost of a higher
   * security level. Never enabled in node or wallet builds. */
  {
    const char *knob = getenv("QUIL_BENCH_LOGDELTA");
    if(knob && knob[0]) logdelta = atof(knob);
  }
#endif
  maxlog = 2*sqrt(LOGQ*logdelta*N)*sqrt(rank);
  maxlog = MIN(LOGQ,maxlog);
  {
    const char *trace=getenv("QUIL_NATIVE_RESOURCE_TRACE");
    if(trace && !strcmp(trace,"1")) {
      fprintf(stderr,"quil_native_sis_instance rank=%zu log2_norm=%.3f max_log2_norm=%.3f secure=%d\n",
              rank,log2(norm),maxlog,log2(norm) < maxlog);
      fflush(stderr);
    }
  }
  if(log2(norm) < maxlog)
    return 1;
  else
    return 0;
}

void update_hash_polz(uint8_t h[HASHLEN], const polz *in, size_t len){
  uint8_t hashbuf[HASHLEN + len * POLZBYTES];
  memcpy(hashbuf, h, HASHLEN);
  polzvec_bitpack(&hashbuf[HASHLEN], in, len);
  shake128(h, HASHLEN, hashbuf, sizeof(hashbuf));
}

void commit(
  polxvec out, 
  const polxvec in
)
{
  polxvec_sprod_extension(out, comkey, in);
}

/*
  Returns how many polynomials of comkey have been used
*/
size_t commit_add(
  polxvec out,
  const polxvec in,
  size_t off_comkey
)
{
  size_t len;
  polxvec comkey_sv;
  polxvec_init_subvec2(comkey_sv, comkey, off_comkey, 1, 0);
  len = polxvec_sprod_extension_add(out, comkey_sv, in);
  polxvec_refresh(out);
  return len;
}

/*
  Allocate and sample matrices jlmat1, jlmat2 that can project a vector  of 
  length len. The matrices correspond to a projection with coefficients 
  distributed in {-1,0,1}. The hash h is updated.

  The matrices are allocated consecutively in memory, i.e., only jlmat1 needs
  to be freed.
*/
void jl_sample_mat(
  uint8_t **jlmat1, 
  uint8_t **jlmat2, 
  uint8_t h[HASHLEN], 
  size_t len
)
{
  uint8_t hashbuf[HASHLEN+SEEDLEN];
  aes256ctr_ctx aesctx;

  *jlmat1 = _aligned_alloc(64, 2 * len * 256 * N / 8);
  shake128(hashbuf, HASHLEN+SEEDLEN, h, HASHLEN);
  memcpy(h, hashbuf, HASHLEN);
  aes256ctr_init(&aesctx, &hashbuf[HASHLEN], 0);
  aes256ctr_select(&aesctx, 0);
  aes256ctr_squeezeblocks(*jlmat1, 2*len*256*N/8 / AES256CTR_BLOCKBYTES, &aesctx);
  *jlmat2 = &(jlmat1[0][len * 256 * N / 8]);
}

/*
  Project vector p of length len into r, where the matrices jlmat are 
  interpreted as a projection with coefficients distributed in {-1,0,1}.
*/
void jl_project(
  int32_t r[256], 
  const poly *p, 
  size_t len, 
  const uint8_t *jlmat1,
  const uint8_t *jlmat2
)
{
  memset(r, 0, 256*sizeof(int32_t));
  polyvec_jlproj_add_bin1(r, p, len, jlmat1, jlmat2);
}

/*
  The output phi is a vector of length len resulting from aggregating the 256
  rows of the matrix jlmat.
*/
void jl_aggregate_mat(
  polxvec phi, 
  const uint8_t *jlmat1,
  const uint8_t *jlmat2, 
  const int64_t chalz[256]
)
{
  size_t i;
  int64_t Q = (1ULL<<LOGQ)-QOFF;
  __attribute__((aligned(64)))
  int64_t chalz_div2[256];
  __int128_t inv2 = (Q+1)/2;
  polxvec tmp;
  
  polxvec_init(tmp, phi->len, 1);

  for(i=0;i<256;i++){
    chalz_div2[i] = cmodq((chalz[i] * inv2) % Q);
  }

  polxvec_jlproj_collapsmat(phi, jlmat1, chalz_div2);
  polxvec_jlproj_collapsmat(tmp, jlmat2, chalz_div2);
  polxvec_add(phi, phi, tmp);
  // Canonicalize the aggregated matrix before later ring multiplications.
  polxvec_refresh(phi);

  polxvec_free(tmp);
}

/*
  The output phi is the linear part that multiplies the binary-decomposed
  projections when checking the correctness of the 256 projection coefficients 
  in a single aggregated constraint. When used, the part corresponding to the
  most significant bit has to be negated.
*/
void jl_aggregate_proj(
  polxvec phi,
  size_t nbits,
  const int64_t chalz[256]
)
{
  size_t i, j;
  int64_t phi64[N];
  polxvec phi_sv, phi_sv2;

  for(i=0;i<256/N;i++){
    phi64[0] = -chalz[N*i];
    for(j=1;j<N;j++){
      phi64[N-j] = chalz[N*i + j];
    }

    polxvec_init_subvec2(phi_sv, phi, i, 1, 1);
    polxvec_fromint64vec2(phi_sv, phi64, 1, 1, WIDTHMOD(LOGQ));
  }

  for(i=1;i<nbits;i++){
    polxvec_init_subvec2(phi_sv, phi, (i-1)*256/N, 1, 256/N);
    polxvec_init_subvec2(phi_sv2, phi, i*256/N, 1, 256/N);
    polxvec_scale(phi_sv2, phi_sv, 2);
  }

  polxvec_refresh(phi);
}

int verify(const statement st, const witness wt){
  size_t i, nn, off;
  int64_t normsq;
  int ret = 1;
  polxvec sxl, *sxq;

  assert(st->r == wt->r);

  // witness to polxvec

  nn = 0;
  for(i=0;i<wt->r;i++){
    nn += wt->n[i];
  }

  polxvec_init(sxl, nn, 1);
  polxvec_frompolyvec(sxl, wt->s[0], 1, nn, 1);

  sxq = _malloc(wt->r * sizeof(polxvec));

  off = 0;
  for(i=0;i<wt->r;i++){
    polxvec_setwidths1(sxl, off, 1, wt->n[i], st->normsq[i]/(st->n[i]*N));
    polxvec_init_subvec2(sxq[i], sxl, off, 1, wt->n[i]);
    off += wt->n[i];
  }

  // norm checks

  for(i=0;i<wt->r;i++){
    normsq = polyvec_sprodz(wt->s[i],wt->s[i],1,1,wt->n[i]);
    if(normsq > (int64_t) st->normsq[i]){
      fprintf(stderr, "ERROR in verify(): norm of witness %zu is larger than " 
                      "the bound (%" PRId64 " > %" PRIu64 ")\n", i, normsq, 
                      st->normsq[i]);
      ret = 0;
    }
  }

  // binary checks

  for(i=0;i<wt->r;i++){
    if(st->normty[i] == BIN){
      if(!polyvec_isbinary(wt->s[i], 1, wt->n[i])){
        fprintf(stderr,"ERROR in verify(): binary check of witness %zu failed\n",
                i);
        ret = 0;
      }
    }
  }

  // Rq constraints checks

  if(!rqcnstset_check(st->rqcnst, sxq, sxl)){
    fprintf(stderr, "ERROR in verify(): check of Rq constraints failed\n");
    ret = 0;
  }

  // Zq constraints checks

  if(!zqcnstset_check(st->zqcnst, sxq, sxl)){
    fprintf(stderr, "ERROR in verify(): check of Zq constraints failed\n");
    ret = 0;
  }

  polxvec_free(sxl);
  free(sxq);
  return ret;
}

void randombits64(int64_t *buf, size_t nbits){
  size_t i, j;
  size_t rbytes = (nbits+7)/8;
  uint8_t bufbytes[rbytes];

  randombytes(bufbytes, rbytes);
  for(i=0;i<rbytes;i++){
    for(j=0;j<MIN(nbits, 8);j++){
      buf[8*i + j] = (bufbytes[i] & ((uint8_t)1 << j)) >> j;
    }
    nbits -= 8;
  }
}

/*
  Samples nchalz uniform integers in Zq and updates the hash.
*/

void sample_chalz(int64_t *chalz, size_t nchalz, uint8_t h[HASHLEN]){
  size_t i, off, len, chunk;
  size_t maxchunk = 100000;
  uint8_t hashbuf[MIN(maxchunk, nchalz)*sizeof(int64_t) + HASHLEN];
  int64_t mask = ((int64_t)1 << 32) - 1;
  
  len = nchalz;
  off = 0;
  while(len > 0){
    chunk = MIN(maxchunk, len);
    shake128(hashbuf, chunk*sizeof(int64_t) + HASHLEN, h, HASHLEN);
    memcpy(h, &hashbuf[chunk*sizeof(int64_t)], HASHLEN);

    for(i=0;i<chunk;i++){
      chalz[off++] = cmodq(((int64_t *)hashbuf)[i] & mask);
    }
    len -= chunk;
  }
}

/*
  Samples chalx->len short polynomials in Rq and updates the hash.
*/
void sample_chalx_aggregate(polxvec chalx, uint8_t h[HASHLEN]){
  uint8_t hashbuf[HASHLEN+SEEDLEN];
  shake128(hashbuf, sizeof(hashbuf), h, HASHLEN);
  memcpy(h, hashbuf, HASHLEN);
  polxvec_challenge(chalx, &hashbuf[HASHLEN], 0);
}

/*
  Samples chalx->len uniform polynomials in Rq and updates the hash.
*/
void sample_chalx_uniform(polxvec chalx, uint8_t h[HASHLEN]){
  uint8_t hashbuf[HASHLEN+SEEDLEN];
  shake128(hashbuf, sizeof(hashbuf), h, HASHLEN);
  memcpy(h, hashbuf, HASHLEN);
  polxvec_almostuniform(chalx, &hashbuf[HASHLEN], 0);
}

/*
  Samples nchalx short polynomials in Rq and updates the hash.
*/
void sample_chalx_amortize(polx *chalx, size_t nchalx, uint8_t h[HASHLEN]){
  size_t i;
  uint8_t hashbuf[HASHLEN+SEEDLEN];
  shake128(hashbuf, sizeof(hashbuf), h, HASHLEN);
  memcpy(h, hashbuf, HASHLEN);
  for(i=0;i<nchalx;i++){
    polx_challenge(chalx[i], &hashbuf[HASHLEN], i);
  }
}

/*
  powers = (v, v*(base), v*(base**2),..., v*(base**(k-1)), v_top*(base**k))
*/
void polxvec_powers(
  polxvec powers, 
  int64_t base, 
  int64_t v, 
  int64_t v_top
)
{
  size_t i;
  int64_t s;

  s = 1;
  for(i=0;i<powers->len - 1;i++){
    polxvec_monomial(powers, i, 0, v * s);
    s *= base;
  }
  polxvec_monomial(powers, powers->len - 1, 0, v_top * s);
}

void outcom_clear(polz a){
  size_t i, j;
  size_t stride = N / SIS1_NCOEF;

  for(i=0;i<N;i++){
    if(i % stride == 0) continue;

    for(j=0;j<L;j++){
      a->limbs[j]->c[i] = 0;
    }
  }
}

void ps_addcheck_commit_in_clear(
  comcnst c,
  const polz *U, 
  size_t rank, 
  size_t pos, 
  size_t len
)
{
  comcnst_init(c, rank, 1, 0, 0);

  c->comk_off[0] = 0;
  c->comw_off[0] = pos;
  c->comw_len[0] = len;

  polzvec_topolxvec(c->b, U, 0, 1, rank);
}

void ps_addcheck_commit_middle(
  comcnst c, 
  size_t rank, 
  size_t cpos,
  size_t wpos, 
  size_t wlen
)
{
  comcnst_init(c, rank, 1, 1, 1);

  c->comk_off[0] = 0;
  c->comw_off[0] = wpos;
  c->comw_len[0] = wlen;

  c->phiw_off[0] = cpos;
  polxvec_init(c->phi[0], LOGQ, 1);
  polxvec_powers(c->phi[0], 2, -1, 1);

  polxvec_setzero(c->b, 0, 1, rank);
}

void ps_addcheck_commit_outer(
  comcnst c,
  size_t cpos,
  size_t wpos,
  size_t wlen,
  size_t base_unif,
  size_t digits_unif
)
{
  comcnst_init(c, 1, 1, 1, 1);

  c->comk_off[0] = 0;
  c->comw_off[0] = wpos;
  c->comw_len[0] = wlen;

  c->phiw_off[0] = cpos;
  polxvec_init(c->phi[0], digits_unif, 1);
  polxvec_powers(c->phi[0], 1<<base_unif, -1, -1);

  polxvec_setzero(c->b, 0, 1, 1);
}

void ps_addcheck_commit_coeffs(
  sparsecnst *c,
  polz outcom,
  size_t wpos,
  size_t base_unif,
  size_t digits_unif
)
{
  size_t i, j, idx;
  size_t stride = N / SIS1_NCOEF;
  zz coeff;
  polz b;
  int64_t phi64[N];
  polxvec phi;

  memset(phi64, 0, sizeof(phi64));

  for(i=0;i<SIS1_NCOEF;i++){
    sparsecnst_init(c[i], 1);
    linfunc_init(c[i]->lin, 1, 1, 1);
    c[i]->lin->off[0] = wpos;
    polxvec_init(c[i]->lin->phi[0], digits_unif, 1);
    
    idx = (i==0) ? 0 : N - stride*i;
    phi64[idx] = (i==0) ? 1 : -1;
    for(j=0;j<digits_unif;j++){ 
      polxvec_init_subvec2(phi, c[i]->lin->phi[0], j, 1, 1);
      polxvec_fromint64vec2(phi, phi64, 1, 1, 1);
      phi64[idx] *= 1 << base_unif;
    }
    phi64[idx] = 0;

    polz_getcoeff(coeff, outcom, stride*i);
    polzvec_setzero(&b, 1);
    polz_setcoeff(b, coeff, 0);
    polzvec_topolxvec(c[i]->b, &b, 0, 1, 1);
  }
}

void ps_addcheck_lift_zero_coeff(sparsecnst c[LIFTS], size_t liftpos){
  int64_t i;
  polxvec powers;

  polxvec_init(powers, LOGQ, 1);
  polxvec_powers(powers, 2, -1, 1);

  for(i=0;i<LIFTS;i++){
    sparsecnst_init(c[i], 1);
    linfunc_init(c[i]->lin, 1, 1, 1);

    c[i]->lin->off[0] = liftpos;
    polxvec_init(c[i]->lin->phi[0], LOGQ, 1);
    polxvec_copy(c[i]->lin->phi[0], powers);

    liftpos += LOGQ;
  }

  polxvec_free(powers);
}

static inline void assert_stwt(statement st, witness wt) {
  #ifndef NDEBUG
  size_t i, nbincnst;

  nbincnst = 0;
  for (i = 0; i < st->r; i++) {
    if (st->normty[i] != BIN)
      continue;
    nbincnst++;
  }

  // enough pre-allocated space in st to account for automorphism vectors
  assert(st->maxr >= st->r + nbincnst);
  assert(st->zqcnst->maxnsparse >= st->zqcnst->nsparse + nbincnst);
  assert(st->zqcnst->maxnsigmam1 >= st->zqcnst->nsigmam1 + nbincnst);

  if (wt == NULL)
    return;

  // enough pre-allocated space in wt to append automorphism vectors
  assert(wt->maxr >= wt->r + nbincnst);

  // wt dimensions match st dimensions
  assert(st->r == wt->r);
  for (i = 0; i < st->r; i++) {
    assert(st->n[i] == wt->n[i]);
  }
  #else
    (void)st;
    (void)wt;
  #endif
}

void compile_bincnst(statement st, witness wt){
  size_t nbin[st->r];
  size_t idxbin[st->r], idxbin1[st->r], idxbin2[st->r];
  size_t nbincnst, i, j, nn, nnbin;
  polxvec monesxvec, phi;
  poly one, mones;
  polx onex;

  assert_stwt(st, wt);

  polxvec_init(monesxvec, 1, 1);

  // collect binary constraints info
  nnbin = 0;
  nn = 0;
  nbincnst = 0;
  for (i = 0; i < st->r; i++) {
    if (st->normty[i] == BIN) {
      idxbin[nbincnst] = i; // index of bin in array
      idxbin1[nbincnst] = nn; // index of bin in concatenated array
      nbin[nbincnst] = st->n[i]; // length of vector
      nbincnst++;
    }
    nn += st->n[i];
  }
  nnbin = 0;
  nbincnst = 0;
  for (i = 0; i < st->r; i++) {
    if (st->normty[i] == BIN) {
      idxbin2[nbincnst] = nn + nnbin; // index of msigma1(bin) in concatenated array
      nbincnst++;

      nnbin += st->n[i];
    }
  }
  if (nbincnst == 0)
    goto ret;

  // compile binary constraints in statement
  memset(one, 0, sizeof(one));
  one->c[0] = 1;
  polx_frompoly(onex, one, 1);

  for (i = 0; i < N; i++)
    mones->c[i] = -1;
  polxvec_frompolyvec(monesxvec, &mones, 1, 1, 1);

  for (i = 0; i < nbincnst; i++) {
    st->n[st->r + i] = nbin[i];
    st->normsq[st->r + i] = N * nbin[i]; // trivial l2 bound on binary
    st->normty[st->r + i] = L2APPROX;

    sigmam1cnst_init(st->zqcnst->sigmam1[st->zqcnst->nsigmam1 + i], idxbin1[i],
                     idxbin2[i], nbin[i], 0);
    st->zqcnst->sigmam1_nchal += nbin[i];

    sparsecnst_init(st->zqcnst->sparse[st->zqcnst->nsparse + i], 1);

    quadfunc_init(st->zqcnst->sparse[st->zqcnst->nsparse + i]->quad, 1, 1);
    st->zqcnst->sparse[st->zqcnst->nsparse + i]->quad->rows[0] = idxbin[i];
    st->zqcnst->sparse[st->zqcnst->nsparse + i]->quad->cols[0] = st->r + i;
    polx_copy(st->zqcnst->sparse[st->zqcnst->nsparse + i]->quad->coeffs[0], onex);

    linfunc_init(st->zqcnst->sparse[st->zqcnst->nsparse + i]->lin, 1, 1, 1);

    st->zqcnst->sparse[st->zqcnst->nsparse + i]->lin->off[0] = idxbin2[i];
    polxvec_init(st->zqcnst->sparse[st->zqcnst->nsparse + i]->lin->phi[0], nbin[i], 1);
    for (j = 0; j < nbin[i]; j++){
      polxvec_init_subvec2(phi, st->zqcnst->sparse[st->zqcnst->nsparse+i]->lin->phi[0], 
                           j, 1, 1);
      polxvec_copy(phi, monesxvec);
    }
  }

  st->r += nbincnst;
  st->zqcnst->nsparse += nbincnst;
  st->zqcnst->nsigmam1 += nbincnst;
  st->zqcnst->sparse_nchal += nbincnst;

  if (wt == NULL)
    goto ret;

  // compile binary constraints in witness
  wt->s[wt->r] = &wt->s[wt->r - 1][wt->n[wt->r - 1]];
  wt->n[wt->r] = nbin[0];
  polyvec_sigmam1(wt->s[wt->r], wt->s[idxbin[0]], 1, 1, nbin[0]);
  for (i = 1; i < nbincnst; i++) {
    wt->n[wt->r + i] = nbin[i];
    wt->s[wt->r + i] = &wt->s[wt->r + i - 1][wt->n[wt->r + i - 1]];
    polyvec_sigmam1(wt->s[wt->r + i], wt->s[idxbin[i]], 1, 1, nbin[i]);
  }
  wt->r += nbincnst;

ret:
  polxvec_free(monesxvec);
}
