#include "labrador.h"
#include "labrador_core.h"
#include "proofsystem.h"
#include "polx.h"
#include "polz.h"
#include "jlproj.h"
#include "malloc.h"
#include "fips202.h"
#include "resource_trace.h"
#include "refresh_parallel.h"
#include "ldr_parallel.h"

void ldr_aggregate_zq(
  sparsecnst zqagg[LIFTS], 
  const statement ist, 
  const uint8_t *jlmat1, 
  const uint8_t *jlmat2,
  const int32_t p[256], 
  size_t nn,
  size_t r_old,
  uint8_t h[HASHLEN]
)
{
  size_t i, nchalz, nchalx, chalz_len, batch;
  int64_t *chalz[LIFTS];
  polxvec chalx[LIFTS];
  quil_ldr_zq_job jobs[LIFTS];
  __attribute__((aligned(64)))
  uint8_t hashbuf[64 + QBYTES*256 + 24];

  nchalz = ist->zqcnst->sparse_nchal + ist->zqcnst->int_nchal;
  nchalx =  ist->zqcnst->sigmam1_nchal;
  chalz_len = 256 + nchalz+64-nchalz%64;
  batch = quil_ldr_zq_batch_size(nn);
  {
    const char *trace=getenv("QUIL_NATIVE_RESOURCE_TRACE");
    if(trace && !strcmp(trace,"1")) {
      fprintf(stderr,"quil_native_ldr_zq_shape nn=%zu scalar_challenges=%zu polynomial_challenges=%zu batch_size=%zu\n",
              nn,nchalz,nchalx,batch);
      fflush(stderr);
    }
  }

  for(size_t base=0;base<LIFTS;base+=batch){
    size_t count = MIN(batch, LIFTS-base);
    for(size_t slot=0;slot<count;slot++){
      i = base+slot;
      chalz[i] = _aligned_alloc(64, chalz_len * sizeof(int64_t));
      memset(chalx[i], 0, sizeof(polxvec));
      if(nchalx > 0){
        polxvec_init(chalx[i], nchalx, 1);
      }

      /* Preserve the original challenge and hash-update order exactly. */
      shake128(hashbuf, sizeof(hashbuf), h, HASHLEN);
      memcpy(h, hashbuf, HASHLEN);
      jlproj_expand_challenge(chalz[i], &hashbuf[64]);
      sample_chalz(&chalz[i][256], nchalz, h);

      sparsecnst_init(zqagg[i], 1);
      quadfunc_init(zqagg[i]->quad, 0, (r_old * r_old + r_old)/2);
      linfunc_init(zqagg[i]->lin, 1, 1, 1);

      zqagg[i]->lin->off[0] = 0;
      polxvec_init(zqagg[i]->lin->phi[0], nn, 1);

      jobs[i] = (quil_ldr_zq_job){.out=zqagg[i], .input=ist->zqcnst,
                                  .jlmat1=jlmat1, .jlmat2=jlmat2, .p=p,
                                  .chalz=chalz[i], .chalx=chalx[i]};
      quil_ldr_zq_prepare_challenge_seed(&jobs[i], h);
    }

    quil_resource_trace("ldr_zq_batch_begin");
    quil_ldr_zq_execute_batch(&jobs[base], count);
    quil_resource_trace("ldr_zq_batch_end");

    for(size_t slot=0;slot<count;slot++){
      i = base+slot;
      zqagg[i]->quad->coeffs = realloc(zqagg[i]->quad->coeffs, 
                                       zqagg[i]->quad->len*sizeof(polx));
      free(chalz[i]);
      if(nchalx > 0){
        polxvec_free(chalx[i]);
      }
    }
  }
}

void ldr_aggregate_rq(
  sparsecnst finalcnst, 
  const statement ist,
  const sparsecnst zqagg[LIFTS],
  size_t nn, 
  size_t r_old,
  uint8_t h[HASHLEN]
)
{
  size_t nchalx;
  polxvec chalx, chalx_sv;

  nchalx = ist->rqcnst->sparse_nchal + ist->rqcnst->com_nchal;
  polxvec_init(chalx, nchalx + LIFTS, 1);
  sample_chalx_aggregate(chalx, h);

  sparsecnst_init(finalcnst, 1);
  quadfunc_init(finalcnst->quad, 0, (r_old * r_old + r_old)/2);
  linfunc_init(finalcnst->lin, 1, 1, 1);

  finalcnst->lin->off[0] = 0;
  polxvec_init(finalcnst->lin->phi[0], nn, 1);
  polxvec_setzero(finalcnst->lin->phi[0], 0, 1, nn);

  polxvec_init_subvec2(chalx_sv, chalx, 0, 1, nchalx);
  rqcnstset_aggregate_add(finalcnst, ist->rqcnst, chalx_sv);

  polxvec_init_subvec2(chalx_sv, chalx, nchalx, 1, LIFTS);
  sparsecnst_aggregate_add(finalcnst, zqagg, LIFTS, chalx_sv, NULL, 1);

  quil_sparsecnst_parallel_refresh(finalcnst);

  finalcnst->quad->coeffs = realloc(finalcnst->quad->coeffs, 
                                    finalcnst->quad->len*sizeof(polx));

  polxvec_free(chalx);
}

static void ldr_addcheck_commit(
  comcnst c[2],
  const lab_params pp,
  const lab_proof pi
)
{
  ps_addcheck_commit_in_clear(c[0], pi->m[0], pp->kappa[1], pp->off[LAB_INCOM],
                              pp->len[LAB_INCOM] + pp->len[LAB_QUADG]);
  ps_addcheck_commit_in_clear(c[1], pi->m[3], pp->kappa[1], pp->off[LAB_LING],
                              pp->len[LAB_LING]);
}

static void ldr_addcheck_system(
  sparsecnst c,
  const lab_params pp,
  const sparsecnst finalcnst
)
{
  size_t i, j, k, l, idx, off, ncoeffs;
  size_t rmap[pp->r_old];
  polxvec powers, gphi;

  sparsecnst_init(c, 1);

  ncoeffs = 0;
  for(i=0;i<finalcnst->quad->len;i++){
    ncoeffs += pp->rr[finalcnst->quad->rows[i]];
  }
  off = 0;
  for(i=0;i<pp->r_old;i++){
    rmap[i] = off;
    off += pp->rr[i];
  }

  linfunc_init(c->lin, 1, ncoeffs + pp->r, ncoeffs + pp->r);

  polxvec_copy(c->b, finalcnst->b);

  idx = 0;

  // gij
  polxvec_init(gphi, pp->fg, 1);
  polxvec_init(powers, pp->fg, 1);
  polxvec_powers(powers, 1 << pp->bg, 1, 1);
  for(k=0;k<finalcnst->quad->len;k++){
    i = finalcnst->quad->rows[k];
    j = finalcnst->quad->cols[k];
    polxvec_polx_mul(gphi, finalcnst->quad->coeffs[k], powers);
    polxvec_refresh(gphi);
    for(l=0;l<pp->rr[i];l++){
      // a[i][j] * g[rmap[i]+l][rmap[j]+l]
      c->lin->off[idx] = pp->off[LAB_QUADG] 
                         + pp->fg * trimat_idx(rmap[i]+l, rmap[j]+l, pp->r);
      polxvec_init(c->lin->phi[idx], pp->fg, 1);
      polxvec_copy(c->lin->phi[idx], gphi);
      idx++;
    }
  }
  polxvec_free(gphi);
  polxvec_free(powers);

  // hii
  polxvec_init(powers, pp->fu, 1);
  polxvec_powers(powers, 1 << pp->bu, 1, 1);
  off = 0;
  for(i=0;i<pp->r;i++){
    c->lin->off[idx] = pp->off[LAB_LING] + off;
    polxvec_init(c->lin->phi[idx], pp->fu, 1);
    polxvec_copy(c->lin->phi[idx], powers);
    off += pp->fu * (pp->r - i);
    idx++;
  }
  polxvec_free(powers);
}

static void ldr_addchecks(
  statement ost,
  const lab_params pp,
  const lab_proof pi,
  polx *chalx_amortize, 
  const polxvec phi[pp->r], 
  const sparsecnst finalcnst
)
{
  rqcnstset_init(ost->rqcnst, 3, 3);

  ost->rqcnst->sparse_nchal = 3;
  ost->rqcnst->com_nchal = pp->kappa[0] + 2*pp->kappa[1];

  ldr_addcheck_commit(ost->rqcnst->com, pp, pi);

  lab_addcheck_amortization(ost->rqcnst->com[2], pp->kappa[0], pp->r,
                        pp->nmax, pp->off[LAB_Z], pp->off[LAB_INCOM],
                        pp->fz, pp->bz, pp->fu, pp->bu, chalx_amortize);

  lab_addcheck_quadg(ost->rqcnst->sparse[0], pp->r, pp->off[LAB_QUADG], pp->fz,
                     pp->bz, pp->fg, pp->bg, chalx_amortize);

  lab_addcheck_ling(ost->rqcnst->sparse[1], pp->r, pp->nmax, pp->off[LAB_Z],
                    pp->off[LAB_LING], pp->fz, pp->bz, pp->fu, pp->bu,
                    chalx_amortize, phi);

  ldr_addcheck_system(ost->rqcnst->sparse[2], pp, finalcnst);
}

void ldr_prove(
  lab_proof pi, 
  statement ost, 
  witness owt, 
  const statement ist,
  const witness iwt, 
  const lab_params pp
)
{
  size_t i, off, tpos;
  uint8_t *jlmat1, *jlmat2, hashbuf[1024];
  poly *sy[pp->r], *sout;
  polx *chalx_amortize;
  polxvec sxl, sxq[pp->r], sxq_old[ist->r], phi[pp->r];
  polxvec tx, u1x, tgd, liftx, u2x, hd, zx;
  sparsecnst zqagg[LIFTS], finalcnst;

  // View input witness with new split

  sy[0] = iwt->s[0];
  for(i=1;i<pp->r;i++){
    sy[i] = &sy[i-1][pp->n[i-1]];
  }

  // Input witness to polx

  polxvec_init(sxl, pp->nn, 1);
  polxvec_frompolyvec(sxl, sy[0], 1, pp->nn, pp->normsq_global/(pp->nn*N));
  
  off = 0;
  for(i=0;i<pp->r;i++){
    polxvec_init_subvec2(sxq[i], sxl, off, 1, pp->n[i]);
    off += pp->n[i];
  }
  off = 0;
  for(i=0;i<ist->r;i++){
    polxvec_init_subvec2(sxq_old[i], sxl, off, 1, ist->n[i]);
    off += ist->n[i];
  }

  // Init

  lab_witness_init(owt, pp);
  lab_proof_init(pi, pp);
  lab_statement_init(ost, ist, pp);
  lab_comkey_init(pp);
  sout = owt->s[0];

  // Inner commitments

  polxvec_init(tx, pp->kappa[0], 1);
  tpos = pp->off[LAB_INCOM];
  for(i=0;i<pp->r;i++){
    commit(tx, sxq[i]);
    polxvec_decompose(&sout[tpos], tx, tx->len, pp->fu, pp->bu);
    tpos += pp->kappa[0] * pp->fu;
  }

  // Quadratic garbage

  lab_quadg(&sout[pp->off[LAB_QUADG]], NULL, sxq, pp->r, pp->fg, pp->bg, 0);


  // Middle commitment u1

  polxvec_init(u1x, pp->kappa[1], 1);
  polxvec_init(tgd, pp->len[LAB_INCOM] + pp->len[LAB_QUADG], 1);
  polxvec_frompolyvec(tgd, &sout[pp->off[LAB_INCOM]], 1, pp->len[LAB_INCOM],
                      WIDTHMOD(pp->bu));
  polxvec_init_subvec(tgd, tgd, pp->len[LAB_INCOM], 1, pp->len[LAB_QUADG]);
  polxvec_frompolyvec(tgd, &sout[pp->off[LAB_QUADG]], 1, pp->len[LAB_QUADG], 
                      WIDTHMOD(pp->bg));
  polxvec_init_subvec(tgd, tgd, 0, 1, 0);
  commit(u1x, tgd);
  polzvec_frompolxvec(pi->m[0], u1x, 0, 1, pp->kappa[1]);

  update_hash_polz(ost->h, pi->m[0], pp->kappa[1]);

  // JL projections

  jl_sample_mat(&jlmat1, &jlmat2, ost->h, pp->nn);
  jl_project(pi->p, sy[0], pp->nn, jlmat1, jlmat2);

  memcpy(hashbuf, pi->p, 1024);
  shake128(ost->h, 16, hashbuf, 1024);

  // Aggregate projections with other Zq constraints

  ldr_aggregate_zq(zqagg, ist, jlmat1, jlmat2, pi->p, pp->nn, pp->r_old, ost->h);

  // Lift constraints

  polxvec_init(liftx, 1, 1);
  for(i=0;i<LIFTS;i++){
    sparsecnst_eval(liftx, zqagg[i], sxq_old, sxl);
    polzvec_frompolxvec(&pi->m[2][i], liftx, 0, 1, 1);
    polxvec_add(zqagg[i]->b, zqagg[i]->b, liftx);
    polxvec_refresh(zqagg[i]->b);
  }
  update_hash_polz(ost->h, pi->m[2], LIFTS);

  // Aggregate Rq constraints

  ldr_aggregate_rq(finalcnst, ist, zqagg, pp->nn, pp->r_old, ost->h);

  off = 0;
  for(i=0;i<pp->r;i++){
    polxvec_init_subvec2(phi[i], finalcnst->lin->phi[0], off, 1, pp->n[i]);
    off += pp->n[i];
  }

  // Linear garbage hij

  lab_ling(&sout[pp->off[LAB_LING]], sxq, phi, pp->r, pp->fu, pp->bu);


  // Middle commitment u2

  polxvec_init(u2x, pp->kappa[1], 1);
  polxvec_init(hd, pp->len[LAB_LING], 1);
  polxvec_frompolyvec(hd, &sout[pp->off[LAB_LING]], 1, pp->len[LAB_LING],
                      WIDTHMOD(pp->bu));
  commit(u2x, hd);
  polzvec_frompolxvec(pi->m[3], u2x, 0, 1, pp->kappa[1]);

  update_hash_polz(ost->h, pi->m[3], pp->kappa[1]);

  // Amortization

  chalx_amortize = _aligned_alloc(64, pp->r * sizeof(polx));
  sample_chalx_amortize(chalx_amortize, pp->r, ost->h);
  
  polxvec_init(zx, pp->nmax, 1);
  polxvec_setzero(zx, 0, 1, pp->nmax);
  for(i=0;i<pp->r;i++){
    polxvec_init_subvec(zx, zx, 0, 1, pp->n[i]);
    polxvec_polx_mul_add(zx, chalx_amortize[i], sxq[i]);
  }
  polxvec_init_subvec(zx, zx, 0, 1, 0);
  polxvec_decompose(&sout[pp->off[LAB_Z]], zx, zx->len, pp->fz, pp->bz);

  // Generate constraints for the verifier's checks

  ldr_addchecks(ost, pp, pi, chalx_amortize, phi, finalcnst);


  for(i=0;i<LIFTS;i++){
    sparsecnst_free(zqagg[i]);
  }
  sparsecnst_free(finalcnst);
  polxvec_free(sxl);
  polxvec_free(tx);
  polxvec_free(u1x);
  polxvec_free(tgd);
  polxvec_free(liftx);
  polxvec_free(u2x);
  polxvec_free(hd);
  polxvec_free(zx);
  free(jlmat1);
  free(chalx_amortize);
}

int ldr_reduce(
  statement ost, 
  const statement ist, 
  const lab_proof pi,
  const lab_params pp
)
{
  size_t i, off;
  uint8_t *jlmat1, *jlmat2, hashbuf[1024];
  int check;
  polx *chalx_amortize;
  polxvec phi[pp->r], liftx, liftx_sv;
  sparsecnst zqagg[LIFTS], finalcnst;

  lab_statement_init(ost, ist, pp);
  lab_comkey_init(pp);

  // Hash commitment u1

  update_hash_polz(ost->h, pi->m[0], pp->kappa[1]);

  // Sample JL matrices

  jl_sample_mat(&jlmat1, &jlmat2, ost->h, pp->nn);

  // Check JL norm

  if(jlproj_normsq(pi->p) > JL_L2_MULT * pp->normsq_global){
    statement_free(ost);
    free(jlmat1);
    return 1;
  }

  // Hash projection

  memcpy(hashbuf, pi->p, 1024);
  shake128(ost->h, 16, hashbuf, 1024);

  // Aggregate projections with other Zq constraints

  ldr_aggregate_zq(zqagg, ist, jlmat1, jlmat2, pi->p, pp->nn, pp->r_old, ost->h);
  free(jlmat1);

  // Update constraints with liftings

  polxvec_init(liftx, LIFTS, 1);
  polzvec_topolxvec(liftx, pi->m[2], 0, 1, LIFTS);

  for(i=0;i<LIFTS;i++){
    polxvec_init_subvec2(liftx_sv, liftx, i, 1, 1);
    polxvec_add(zqagg[i]->b, zqagg[i]->b, liftx_sv);
    polxvec_refresh(zqagg[i]->b);
  }

  // Check liftings

  check = 1;
  for(i=0;i<LIFTS;i++){
    check &= polxvec_iszero_constcoeff(liftx, i);
  }
  polxvec_free(liftx);

  if(!check){
    statement_free(ost);
    for(i=0;i<LIFTS;i++){
      sparsecnst_free(zqagg[i]);
    }
    return 2;
  }

  // Hash liftings

  update_hash_polz(ost->h, pi->m[2], LIFTS);

  // Aggregate Rq constraints

  ldr_aggregate_rq(finalcnst, ist, zqagg, pp->nn, pp->r_old, ost->h);

  off = 0;
  for(i=0;i<pp->r;i++){
    polxvec_init_subvec2(phi[i], finalcnst->lin->phi[0], off, 1, pp->n[i]);
    off += pp->n[i];
  }

  // Hash commitment u2

  update_hash_polz(ost->h, pi->m[3], pp->kappa[1]);  

  // Sample challenges for amortization

  chalx_amortize = _aligned_alloc(64, pp->r * sizeof(polx));
  sample_chalx_amortize(chalx_amortize, pp->r, ost->h);

  // Generate constraints for the verifier's checks

  ldr_addchecks(ost, pp, pi, chalx_amortize, phi, finalcnst);

  // free

  for(i=0;i<LIFTS;i++){
    sparsecnst_free(zqagg[i]);
  }
  sparsecnst_free(finalcnst);
  free(chalx_amortize);

  return 0;
}
