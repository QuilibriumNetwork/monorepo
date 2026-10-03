#include "labrador_tail.h"
#include "labrador.h"
#include "labrador_core.h"
#include "proofsystem.h"
#include "polx.h"
#include "polz.h"
#include "jlproj.h"
#include "malloc.h"
#include "fips202.h"
#include "inttypes.h"

static void ldr_tail_amortize(
  polz *hz,
  poly *zy,
  polx *chalx_amortize,
  polxvec phi_amortize,
  uint8_t hash[HASHLEN], 
  const polxvec sx[], 
  const polxvec phi[], 
  const lab_params pp
)
{
  size_t i;
  polxvec hx, zx, zx_sv, phi_sv;

  polxvec_init(hx, 1, 1);
  polxvec_init(zx, phi_amortize->len, 1);

  polxvec_setzero(zx, 0, 1, zx->len);
  polxvec_setzero(phi_amortize, 0, 1, phi_amortize->len);

  // h_0 = <phi[0], sx[0]>
  polxvec_sprod(hx, phi[0], sx[0]);
  polzvec_frompolxvec(&hz[0], hx, 0, 1, 1);

  update_hash_polz(hash, &hz[0], 1);
  sample_chalx_amortize(&chalx_amortize[0], 1, hash);

  // z = c_0 * sx[0]
  polxvec_init_subvec(zx, zx, 0, 1, pp->n[0]);
  polxvec_polx_mul(zx, chalx_amortize[0], sx[0]);
  polxvec_init_subvec(zx, zx, 0, 1, 0);

  // phi_amortize = c_0 * phi[0]
  polxvec_init_subvec(phi_amortize, phi_amortize, 0, 1, pp->n[0]);
  polxvec_polx_mul(phi_amortize, chalx_amortize[0], phi[0]);
  polxvec_init_subvec(phi_amortize, phi_amortize, 0, 1, 0);

  for(i=1;i<pp->r;i++){
    // h_(2*i-1) = <phi[i], z> + <phi_amortize, sx[i]>
    polxvec_init_subvec2(zx_sv, zx, 0, 1, pp->n[i]);
    polxvec_init_subvec2(phi_sv, phi_amortize, 0, 1, pp->n[i]);
    polxvec_sprod(hx, phi[i], zx_sv);
    polxvec_sprod_add(hx, phi_sv, sx[i]);
    polzvec_frompolxvec(&hz[2*i-1], hx, 0, 1, 1);

    // h_(2*i) = <phi[i], sx[i]>
    polxvec_sprod(hx, phi[i], sx[i]);
    polzvec_frompolxvec(&hz[2*i], hx, 0, 1, 1);

    update_hash_polz(hash, &hz[2*i-1], 2);
    sample_chalx_amortize(&chalx_amortize[i], 1, hash);

    // z += c_i * sx[i]
    polxvec_polx_mul_add(zx_sv, chalx_amortize[i], sx[i]);

    // phi_amortize += c_i * phi[i]
    polxvec_polx_mul_add(phi_sv, chalx_amortize[i], phi[i]);
  }

  polxvec_decompose(zy, zx, zx->len, pp->fz, pp->bz);

  polxvec_free(hx);
  polxvec_free(zx);
}

static void ldr_tail_reduce_amortize(
  polx *chalx_amortize,
  polxvec phi_amortize,
  uint8_t hash[HASHLEN],
  const polz *hz,
  const polxvec *phi,
  size_t r
)
{
  size_t i;

  update_hash_polz(hash, &hz[0], 1);
  sample_chalx_amortize(&chalx_amortize[0], 1, hash);
  for(i=1;i<r;i++){
    update_hash_polz(hash, &hz[2*i-1], 2);
    sample_chalx_amortize(&chalx_amortize[i], 1, hash);
  }

  polxvec_setzero(phi_amortize, 0, 1, phi_amortize->len);
  for(i=0;i<r;i++){
    polxvec_init_subvec(phi_amortize, phi_amortize, 0, 1, phi[i]->len);
    polxvec_polx_mul_add(phi_amortize, chalx_amortize[i], phi[i]);
  }
  polxvec_init_subvec(phi_amortize, phi_amortize, 0, 1, 0);
}

static void ldr_tail_addcheck_amortization(
  comcnst c,
  const lab_params pp,
  const polz *tz,
  polx chalx[pp->r]
)
{
  size_t i;
  polxvec tx;

  comcnst_init(c, pp->kappa[0], pp->fz, 0, 0);

  c->comk_off[0] = 0;
  c->comw_off[0] = pp->off[LAB_Z];
  c->comw_len[0] = pp->nmax;

  if(pp->fz == 2){
    c->comk_off[1] = 0;
    c->comw_off[1] = pp->off[LAB_Z] + pp->nmax;
    c->comw_len[1] = pp->nmax;
    c->scalar[1] = 1 << pp->bz;
  }

  polxvec_setzero(c->b, 0, 1, pp->kappa[0]);
  polxvec_init(tx, pp->kappa[0], 1);
  for(i=0;i<pp->r;i++){
    polzvec_topolxvec(tx, &tz[i * pp->kappa[0]], 0, 1, pp->kappa[0]);
    polxvec_polx_mul_add(c->b, chalx[i], tx);
  }
  polxvec_refresh(c->b);

  polxvec_free(tx);
}

static void ldr_tail_addcheck_quadg(
  sparsecnst c,
  const lab_params pp,
  const polz *gz,
  polx chalx[pp->r]
)
{
  size_t i, j, off;
  polx cprod, cdouble;
  polxvec gx;

  sparsecnst_init(c, 1);
  quadfunc_init(c->quad, (pp->fz == 2) ? 3 : 1, (pp->fz == 2) ? 3 : 1);

  c->quad->rows[0] = 0;
  c->quad->cols[0] = 0;
  polx_monomial(c->quad->coeffs[0], 0, 1);

  if(pp->fz == 2){
    c->quad->rows[1] = 1;
    c->quad->cols[1] = 1;
    polx_monomial(c->quad->coeffs[1], 0, (1<<pp->bz)*(1<<pp->bz));

    c->quad->rows[2] = 0;
    c->quad->cols[2] = 1;
    polx_monomial(c->quad->coeffs[2], 0, 2*(1<<pp->bz));
  }

  polxvec_init(gx, 1, 1);

  off = 0;
  for(i=0;i<pp->r;i++){
    polzvec_topolxvec(gx, &gz[off], 0, 1, 1);
    polx_mul(cprod, chalx[i], chalx[i]);
    polxvec_polx_mul_add(c->b, cprod, gx);
    off++;

    polx_scale(cdouble, chalx[i], 2);
    for(j=i+1;j<pp->r;j++){
      polzvec_topolxvec(gx, &gz[off], 0, 1, 1);
      polx_mul(cprod, cdouble, chalx[j]);
      polxvec_polx_mul_add(c->b, cprod, gx);
      off++;
    }
  }
  polxvec_free(gx);
}

static void ldr_tail_addcheck_ling(
  sparsecnst c,
  const lab_params pp,
  const polz *hz,
  polx chalx[pp->r],
  const polxvec phi_amortize
)
{
  size_t i;
  polx csquare;
  polxvec hx;

  sparsecnst_init(c, 1);
  linfunc_init(c->lin, 1, pp->fz, pp->fz);
  
  c->lin->off[0] = 0;
  polxvec_init(c->lin->phi[0], pp->nmax, 1);
  polxvec_copy(c->lin->phi[0], phi_amortize);

  if(pp->fz == 2){
    c->lin->off[1] = pp->off[LAB_Z] + pp->nmax;
    polxvec_init(c->lin->phi[1], pp->nmax, 1);
    polxvec_scale(c->lin->phi[1], phi_amortize, 1 << pp->bz);
  }

  polxvec_init(hx, 1, 1);

  polzvec_topolxvec(hx, &hz[0], 0, 1, 1);
  polx_mul(csquare, chalx[0], chalx[0]);
  polxvec_polx_mul(c->b, csquare, hx);

  for(i=1;i<pp->r;i++){
    polzvec_topolxvec(hx, &hz[2*i-1], 0, 1, 1);
    polxvec_polx_mul_add(c->b, chalx[i], hx);

    polzvec_topolxvec(hx, &hz[2*i], 0, 1, 1);
    polx_mul(csquare, chalx[i], chalx[i]);
    polxvec_polx_mul_add(c->b, csquare, hx);
  }

  polxvec_free(hx);
}

static void ldr_tail_addchecks(
  statement ost,
  const lab_params pp,
  const lab_proof pi,
  polx *chalx_amortize,
  const polxvec phi_amortize
)
{
  rqcnstset_init(ost->rqcnst, 2, 1);

  ost->rqcnst->sparse_nchal = 2;
  ost->rqcnst->com_nchal = pp->kappa[0];

  ldr_tail_addcheck_amortization(ost->rqcnst->com[0],pp,pi->m[0],chalx_amortize);

  ldr_tail_addcheck_quadg(ost->rqcnst->sparse[0], pp, 
                          &pi->m[0][pp->len[LAB_INCOM]], chalx_amortize);

  ldr_tail_addcheck_ling(ost->rqcnst->sparse[1], pp, pi->m[3], chalx_amortize,
                         phi_amortize);
}

static int ldr_tail_check_system(
  const sparsecnst finalcnst, 
  const lab_proof pi, 
  const lab_params pp
)
{
  size_t i, j, k, l, off;
  size_t rmap[pp->r_old];
  int check;
  polxvec ev, gx, hx;
  polz *gz, *hz;

  gz = &pi->m[0][pp->len[LAB_INCOM]];
  hz = pi->m[3];

  polxvec_init(ev, 1, 1);
  polxvec_init(gx, 1, 1);
  polxvec_init(hx, 1, 1);

  off = 0;
  for(i=0;i<pp->r_old;i++){
    rmap[i] = off;
    off += pp->rr[i];
  }

  polxvec_setzero(ev, 0, 1, 1);

  // ev = \sum_ij a_ij g_ij
  for(k=0;k<finalcnst->quad->len;k++){
    i = finalcnst->quad->rows[k];
    j = finalcnst->quad->cols[k];
    for(l=0;l<pp->rr[i];l++){
      polzvec_topolxvec(gx,&gz[trimat_idx(rmap[i]+l, rmap[j]+l, pp->r)],0,1,1);
      polxvec_polx_mul_add(ev, finalcnst->quad->coeffs[k], gx);
      polxvec_refresh(ev);
    }
  }

  // ev += \sum_i h_ii
  for(i=0;i<pp->r;i++){
    polzvec_topolxvec(hx, &hz[2*i], 0, 1, 1);
    polxvec_add(ev, ev, hx);
  }

  // ev -= b
  polxvec_sub(ev, ev, finalcnst->b);

  check = polxvec_iszero(ev);

  polxvec_free(ev);
  polxvec_free(gx);
  polxvec_free(hx);

  return check;
}

void ldr_tail_prove(
  lab_proof pi, 
  statement ost,
  witness owt,
  const statement ist, 
  const witness iwt,
  const lab_params pp
)
{
  size_t i, off;
  uint8_t *jlmat1, *jlmat2, hashbuf[1024];
  poly *sy[pp->r], *sout;
  polx *chalx_amortize;
  polxvec sxl, sxq[pp->r], sxq_old[ist->r], phi[pp->r], phi_amortize, tx, liftx;
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
  for(i=0;i<pp->r;i++){
    commit(tx, sxq[i]);
    polzvec_frompolxvec(&pi->m[0][pp->kappa[0] * i], tx, 0, 1, pp->kappa[0]);
  }

  // Quadratic garbage

  lab_quadg(NULL, &pi->m[0][pp->len[LAB_INCOM]], sxq, pp->r, 0, 0, 1);

  update_hash_polz(ost->h, pi->m[0], 
                   pp->len[LAB_INCOM] + pp->len[LAB_QUADG]);

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

  // Linear garbage and amortization

  chalx_amortize = _aligned_alloc(64, pp->r * sizeof(polx));
  polxvec_init(phi_amortize, pp->nmax, 1);
  ldr_tail_amortize(pi->m[3],sout,chalx_amortize,phi_amortize,ost->h,sxq,phi,pp);

  // Generate constraints for the verifier's checks
  
  ldr_tail_addchecks(ost, pp, pi, chalx_amortize, phi_amortize);

  for(i=0;i<LIFTS;i++){
    sparsecnst_free(zqagg[i]);
  }
  sparsecnst_free(finalcnst);
  polxvec_free(sxl);
  polxvec_free(tx);
  polxvec_free(liftx);
  polxvec_free(phi_amortize);
  free(jlmat1);
  free(chalx_amortize);
}

int ldr_tail_reduce(
  statement ost,
  const statement ist,
  const lab_proof pi,
  const lab_params pp
)
{
  size_t i, off;
  uint8_t *jlmat1, *jlmat2, hashbuf[1024];
  polx *chalx_amortize;
  polxvec phi[pp->r], phi_amortize, liftx, liftx_sv;
  sparsecnst zqagg[LIFTS], finalcnst;
  int check, ret;

  lab_statement_init(ost, ist, pp);
  lab_comkey_init(pp);

  // Hash first message

  update_hash_polz(ost->h, pi->m[0], 
                   pp->len[LAB_INCOM] + pp->len[LAB_QUADG]);

  // Sample JL matrices

  jl_sample_mat(&jlmat1, &jlmat2, ost->h, pp->nn);

  // Check JL norm

  if(jlproj_normsq(pi->p) > JL_L2_MULT * pp->normsq_global){
    fprintf(stderr, "ERROR in ldr_tail_reduce(): norm of the projection is " 
                    "larger than the bound (%" PRId64 " > %" PRIu64 ")\n", 
                    jlproj_normsq(pi->p), JL_L2_MULT * pp->normsq_global);
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
    fprintf(stderr, "ERROR in ldr_tail_reduce(): the constant coefficient of " 
                    "the liftings is not 0\n");
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

  // Reduce linear garbage and amortization

  chalx_amortize = _aligned_alloc(64, pp->r * sizeof(polx));
  polxvec_init(phi_amortize, pp->nmax, 1);
  ldr_tail_reduce_amortize(chalx_amortize,phi_amortize,ost->h,pi->m[3],phi,pp->r);

  // Generate constraints for the verifier's checks
  
  ldr_tail_addchecks(ost, pp, pi, chalx_amortize, phi_amortize);

  sparsecnst_refresh(finalcnst);
  ret = ldr_tail_check_system(finalcnst, pi, pp) ? 0 : 3;
  if(ret){
    fprintf(stderr, "ERROR in ldr_tail_reduce(): the system check is not " 
                    "satisfied\n");
  }

  for(i=0;i<LIFTS;i++){
    sparsecnst_free(zqagg[i]);
  }
  sparsecnst_free(finalcnst);
  polxvec_free(phi_amortize);
  free(chalx_amortize);

  return ret;
}