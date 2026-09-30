#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "malloc.h"
#include "resource_trace.h"
#include <inttypes.h>
#include "timing.h"
#include "proofsystem.h"
#include "labrador_core.h"
#include "labradoodle.h"
#include "fips202.h"
#include "jlproj.h"
#include "poly.h"
#include "polx.h"
#include "polz.h"
#include "zq_parallel.h"
#include "refresh_parallel.h"
#include "jl_parallel.h"


static void ldd_collapse_jl(
  polxvec jlmat_agg[LIFTS],
  polxvec phi_jlproj[LIFTS],
  size_t nmax, 
  size_t jlbits_max,
  const uint8_t *jlmat1,
  const uint8_t *jlmat2,
  uint8_t h[HASHLEN]
)
{
  quil_collapse_jl(jlmat_agg,phi_jlproj,nmax,jlbits_max,jlmat1,jlmat2,h);
}

static void ldd_aggregate_zq(
  sparsecnst *zqagg,
  polxvec phi_jlproj_full[LIFTS],
  const polxvec phi_jlproj[LIFTS],
  const size_t *jlbits,
  const lab_params pp,
  const statement ist,
  int64_t chalz_jl[LIFTS][LIFTS*pp->r],
  uint8_t h[HASHLEN]
)
{
  size_t i, j, k, nchalz, nchalx, off, len;
  int64_t *chalz[QUIL_ZQ_MAX_JOBS];
  polxvec chalx[QUIL_ZQ_MAX_JOBS], phi;
  timing time;

  nchalz = ist->zqcnst->sparse_nchal + ist->zqcnst->int_nchal;
  nchalx = ist->zqcnst->sigmam1_nchal;

  size_t batch_size=quil_zq_batch_size(nchalz,nchalx);
  const char *trace=getenv("QUIL_NATIVE_RESOURCE_TRACE");
  if(trace && !strcmp(trace,"1")) {
    fprintf(stderr,"quil_native_zq_shape scalar_challenges=%zu polynomial_challenges=%zu sparse=%zu sigma=%zu integer=%zu batch_size=%zu\n",
            nchalz,nchalx,ist->zqcnst->nsparse,ist->zqcnst->nsigmam1,ist->zqcnst->nint,batch_size);
    fflush(stderr);
  }

  for(size_t base=0;base<LIFTS;base+=batch_size) {
    size_t count=MIN(batch_size,LIFTS-base);
    quil_zq_job jobs[QUIL_ZQ_MAX_JOBS];
    for(size_t slot=0;slot<count;slot++) {
      i=base+slot;
      chalz[slot]=nchalz ? _malloc(nchalz*sizeof(int64_t)) : NULL;
      memset(chalx[slot],0,sizeof(polxvec));
      if(nchalx)polxvec_init(chalx[slot],nchalx,1);
      sparsecnst_init(zqagg[i],1);
      quadfunc_init(zqagg[i]->quad,0,(pp->r_old*pp->r_old+pp->r_old)/2);
      linfunc_init(zqagg[i]->lin,1,1,1);
      zqagg[i]->lin->off[0]=0;
      polxvec_init(zqagg[i]->lin->phi[0],pp->nn,1);
      polxvec_setzero(zqagg[i]->lin->phi[0],0,1,pp->nn);
      /* Preserve the original challenge and hash-update order exactly. */
      sample_chalz(chalz[slot],nchalz,h);
      jobs[slot]=(quil_zq_job){.out=zqagg[i],.input=ist->zqcnst,
                              .chalz=chalz[slot],.chalx=chalx[slot]};
      if(count>1)quil_zq_prepare_challenge_seed(&jobs[slot],h);
      else if(nchalx)sample_chalx_uniform(chalx[slot],h);
    }
    quil_resource_trace("ldd_zq_batch_begin");
    quil_zq_execute_batch(jobs,count);
    quil_resource_trace("ldd_zq_batch_end");
    for(size_t slot=0;slot<count;slot++) {
      i=base+slot;
      zqagg[i]->quad->coeffs=realloc(zqagg[i]->quad->coeffs,
                                   zqagg[i]->quad->len*sizeof(polx));
      free(chalz[slot]);
      if(nchalx)polxvec_free(chalx[slot]);
    }
  }

  timing_start(&time, "Aggregate phi for the projections");

  sample_chalz(chalz_jl[0], LIFTS*LIFTS*pp->r, h);

  for(i=0;i<LIFTS;i++){
    polxvec_init(phi_jlproj_full[i], pp->len[LAB_PROJ], 1);
  }

  for(i=0;i<LIFTS;i++){
    off = 0;
    for(j=0;j<pp->r;j++){
      len = (jlbits[j]-1) * 256/N;
      polxvec_init_subvec2(phi, phi_jlproj[i], 0, 1, len);
      for(k=0;k<LIFTS;k++){
        polxvec_init_subvec(phi_jlproj_full[k], phi_jlproj_full[k], off, 1, len);
        if(i==0){
          polxvec_scale(phi_jlproj_full[k], phi, chalz_jl[k][i*pp->r + j]);
        }
        else{
          polxvec_scale_add(phi_jlproj_full[k], phi, chalz_jl[k][i*pp->r + j]);
        }
      }
      off += len;

      // high-order bit is negated
      len = 256/N;
      polxvec_init_subvec2(phi, phi_jlproj[i], (jlbits[j]-1) * 256/N, 1, len);
      for(k=0;k<LIFTS;k++){
        polxvec_init_subvec(phi_jlproj_full[k], phi_jlproj_full[k], off, 1, len);
        if(i==0){
          polxvec_scale(phi_jlproj_full[k], phi, -chalz_jl[k][i*pp->r + j]);
        }
        else{
          polxvec_scale_add(phi_jlproj_full[k], phi, -chalz_jl[k][i*pp->r + j]);
        }
      }
      off += len;
    }
  }
  for(k=0;k<LIFTS;k++){
    polxvec_init_subvec(phi_jlproj_full[k], phi_jlproj_full[k], 0, 1, 0);
    polxvec_refresh(phi_jlproj_full[k]);
  }

  timing_end(&time);
  timing_print(&time, 4);

}

static void ldd_aggregate_rq(
  sparsecnst finalcnst,
  polxvec chalx_zq,
  const lab_params pp,
  const statement ist,
  const sparsecnst zqagg[LIFTS],
  uint8_t h[HASHLEN]
)
{
  size_t nchalx;
  polxvec chalx, chalx_sv;
  timing time;

  timing_start(&time, "Init");

  nchalx = ist->rqcnst->sparse_nchal + ist->rqcnst->com_nchal;
  polxvec_init(chalx, nchalx + LIFTS, 1);
  sample_chalx_aggregate(chalx, h);

  sparsecnst_init(finalcnst, 1);
  quadfunc_init(finalcnst->quad, 0, (pp->r_old * pp->r_old + pp->r_old)/2);
  linfunc_init(finalcnst->lin, 1, 1, 1);

  timing_end(&time);
  timing_print(&time, 4);

  timing_start(&time, "Set constraint to 0s");

  finalcnst->lin->off[0] = 0;
  polxvec_init(finalcnst->lin->phi[0], pp->nn, 1);
  polxvec_setzero(finalcnst->lin->phi[0], 0, 1, pp->nn);

  timing_end(&time);
  timing_print(&time, 4);

  timing_start(&time, "Aggregate input");
  quil_resource_trace("rq_input_begin");

  polxvec_init_subvec2(chalx_sv, chalx, 0, 1, nchalx);
  rqcnstset_aggregate_add(finalcnst, ist->rqcnst, chalx_sv);
  
  quil_resource_trace("rq_input_end");
  timing_end(&time);
  timing_print(&time, 4);

  timing_start(&time, "Aggregate Zq into Rq");
  quil_resource_trace("rq_zq_merge_begin");

  polxvec_init_subvec2(chalx_sv, chalx, nchalx, 1, LIFTS);
  sparsecnst_aggregate_add(finalcnst, zqagg, LIFTS, chalx_sv, NULL, 1);

  quil_resource_trace("rq_zq_merge_end");
  timing_end(&time);
  timing_print(&time, 4);

  timing_start(&time, "Refresh");
  quil_resource_trace("rq_refresh_begin");

  quil_sparsecnst_parallel_refresh(finalcnst);

  quil_resource_trace("rq_refresh_end");
  timing_end(&time);
  timing_print(&time, 4);

  finalcnst->quad->coeffs = realloc(finalcnst->quad->coeffs, 
                                    finalcnst->quad->len*sizeof(polx));

  polxvec_copy(chalx_zq, chalx_sv);

  polxvec_free(chalx);
}

static inline void ldd_ling_jl_add(
  polxvec hx,
  polxvec acc,
  size_t idx_phi,
  size_t idx_sx,
  size_t r,
  const int64_t chalz_jl[LIFTS][LIFTS*r],
  const polxvec chalx_zq,
  const polxvec jl_sprod_sx[LIFTS][r]
)
{
  size_t i, j;
  polxvec chalx;

  for(i=0;i<LIFTS;i++){
    polxvec_scale(acc, jl_sprod_sx[0][idx_sx], chalz_jl[i][idx_phi]);
    for(j=1;j<LIFTS;j++){
      polxvec_scale_add(acc, jl_sprod_sx[j][idx_sx], chalz_jl[i][r*j+idx_phi]);
    }
    polxvec_init_subvec2(chalx, chalx_zq, i, 0, 1);
    polxvec_mul_add(hx, chalx, acc);
  }
}

static void ldd_ling(
  poly *hy,
  size_t r, 
  size_t fu, 
  size_t bu,
  const polxvec sx[], 
  const polxvec phi[],
  const polxvec chalx_zq,
  const polxvec jl_sprod_sx[LIFTS][r],
  const int64_t chalz_jl[LIFTS][LIFTS*r]
)
{
  polxvec hx, acc, phi_sv, sx_sv;
  size_t i, j, len, hpos = 0;

  polxvec_init(hx, 1, 1);
  polxvec_init(acc, 1, 1);

  for(i=0;i<r;i++){
    for(j=i;j<r;j++){
      if(i == j){
        polxvec_sprod(hx, phi[i], sx[i]);
        ldd_ling_jl_add(hx, acc, i, i, r, chalz_jl, chalx_zq, jl_sprod_sx);
      }
      else{
        len = MIN(phi[i]->len, sx[j]->len);
        polxvec_init_subvec2(phi_sv, phi[i], 0, 1, len);
        polxvec_init_subvec2(sx_sv, sx[j], 0, 1, len);
        polxvec_sprod(hx, phi_sv, sx_sv);

        len = MIN(phi[j]->len, sx[i]->len);
        polxvec_init_subvec2(phi_sv, phi[j], 0, 1, len);
        polxvec_init_subvec2(sx_sv, sx[i], 0, 1, len);
        polxvec_sprod_add(hx, phi_sv, sx_sv);

        ldd_ling_jl_add(hx, acc, i, j, r, chalz_jl, chalx_zq, jl_sprod_sx);
        ldd_ling_jl_add(hx, acc, j, i, r, chalz_jl, chalx_zq, jl_sprod_sx);
      }

      polxvec_decompose(&hy[hpos], hx, 1, fu, bu);
      hpos += fu;
    }
  }
  polxvec_free(hx);
  polxvec_free(acc);
}

static void ldd_addcheck_commit(
  comcnst c[6],
  sparsecnst czq[4*SIS1_NCOEF], 
  const lab_params pp,
  const lab_proof pi
)
{
  size_t i;

  ps_addcheck_commit_outer(c[0], pp->off[LAB_OUTCOM], pp->off[LAB_U1],
                           pp->len[LAB_U1] + pp->len[LAB_RAND1], pp->bu, pp->fu);
  ps_addcheck_commit_outer(c[1], pp->off[LAB_OUTCOM]+pp->fu, pp->off[LAB_PROJ],
                           pp->len[LAB_PROJ]+pp->len[LAB_RAND2], pp->bu, pp->fu);
  ps_addcheck_commit_outer(c[2], pp->off[LAB_OUTCOM]+2*pp->fu, pp->off[LAB_LIFT],
                           pp->len[LAB_LIFT]+pp->len[LAB_RAND3], pp->bu, pp->fu);
  ps_addcheck_commit_outer(c[3], pp->off[LAB_OUTCOM]+3*pp->fu, pp->off[LAB_U2],
                           pp->len[LAB_U2]+pp->len[LAB_RAND4], pp->bu, pp->fu);

  ps_addcheck_commit_middle(c[4], pp->kappa[1], pp->off[LAB_U1], 
                    pp->off[LAB_INCOM], pp->len[LAB_INCOM]+pp->len[LAB_QUADG]);
  ps_addcheck_commit_middle(c[5], pp->kappa[1], pp->off[LAB_U2],
                            pp->off[LAB_LING], pp->len[LAB_LING]);

  for(i=0;i<4;i++){
    ps_addcheck_commit_coeffs(&czq[i*SIS1_NCOEF], *pi->m[i], 
                              pp->off[LAB_OUTCOM] + i*pp->fu, pp->bu, pp->fu);
  }
}

static void ldd_addcheck_ling(
  sparsecnst c,
  const lab_params pp,
  const int64_t chalz_jl[LIFTS][LIFTS*pp->r],
  polx chalx_amortize[pp->r],
  const polxvec chalx_zq,
  const polxvec phi[pp->r],
  const polxvec jlmat_agg[LIFTS]
)
{
  size_t i, j, k, off;
  polx cprod;
  polxvec powers, phi_sv, chalx_sv, acc1, acc2;

  sparsecnst_init(c, 1);
  linfunc_init(c->lin, 1, pp->fz + 1, pp->fz + 1);

  c->lin->off[0] = pp->off[LAB_Z];
  polxvec_init(c->lin->phi[0], pp->nmax, 1);
  polxvec_setzero(c->lin->phi[0], 0, 1, c->lin->phi[0]->len);

  for(i=0;i<pp->r;i++){
    polxvec_init_subvec(c->lin->phi[0], c->lin->phi[0], 0, 1, phi[i]->len);
    polxvec_polx_mul_add(c->lin->phi[0], chalx_amortize[i], phi[i]);
  }
  polxvec_init_subvec(c->lin->phi[0], c->lin->phi[0], 0, 1, 0);

  // add contribution of the projection matrices to phi

  polxvec_init(acc1, 1, 1);
  polxvec_init(acc2, 1, 1);

  for(k=0;k<LIFTS;k++){
    for(i=0;i<pp->r;i++){
      for(j=0;j<LIFTS;j++){
        polxvec_init_subvec2(chalx_sv, chalx_zq, j, 1, 1);
        if(j==0){
          polxvec_scale(acc1, chalx_sv, chalz_jl[j][pp->r*k + i]);
        }
        else{
          polxvec_scale_add(acc1, chalx_sv, chalz_jl[j][pp->r*k + i]);
        }
      }
      if(i==0){
        polxvec_polx_mul(acc2, chalx_amortize[i], acc1);
      }
      else{
        polxvec_polx_mul_add(acc2, chalx_amortize[i], acc1);
      }
    }
    polxvec_refresh(acc2);
    // acc2 in LOGQ bits, jlmat_agg in 40 bits; sliced mul-add plus refresh.
    quil_polxvec_parallel_mul_add_refresh(c->lin->phi[0], acc2, jlmat_agg[k]);
  }

  if(pp->fz == 2){
    c->lin->off[1] = pp->off[LAB_Z] + pp->nmax;
    polxvec_init(c->lin->phi[1], pp->nmax, 1);
    polxvec_scale(c->lin->phi[1], c->lin->phi[0], 1<<pp->bz);
  }

  c->lin->off[pp->fz] = pp->off[LAB_LING];
  polxvec_init(c->lin->phi[pp->fz], (pp->r*pp->r + pp->r)/2 * pp->fu, 1);

  polxvec_init(powers, pp->fu, 1);
  polxvec_powers(powers, 1 << pp->bu, -1, -1);

  off = 0;
  for(i=0;i<pp->r;i++){
    for(j=i;j<pp->r;j++){
      // no need to multiply by 2 the non-diagonal since those hij are already
      // multiplied by 2 when computed
      polx_mul(cprod, chalx_amortize[i], chalx_amortize[j]);
      polxvec_init_subvec2(phi_sv, c->lin->phi[pp->fz], off, 1, pp->fu);
      polxvec_polx_mul(phi_sv, cprod, powers);
      off += pp->fu;
    }
  }
  polxvec_free(acc1);
  polxvec_free(acc2);
  polxvec_free(powers);
}

static void ldd_addcheck_system(
  sparsecnst c,
  const lab_params pp,
  const sparsecnst finalcnst,
  const polxvec chalx,
  const polxvec phi_jl[LIFTS]
)
{
  size_t i, j, k, l, idx, off, ncoeffs;
  size_t rmap[pp->r_old];
  polxvec powers, chalx_sv, phi_sv, gphi;

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

  linfunc_init(c->lin, 1, ncoeffs + pp->r + 2, ncoeffs + pp->r + 2);

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

  // liftings
  c->lin->off[idx] = pp->off[LAB_LIFT];
  polxvec_init(c->lin->phi[idx], pp->len[LAB_LIFT], 1);
  
  polxvec_init(powers, LOGQ, 1);
  polxvec_powers(powers, 2, -1, 1);
  for(i=0;i<LIFTS;i++){
    polxvec_init_subvec2(chalx_sv, chalx, i, 1, 1);
    polxvec_init_subvec2(phi_sv, c->lin->phi[idx], i * LOGQ, 1, LOGQ);
    polxvec_mul(phi_sv, chalx_sv, powers);
  }
  polxvec_free(powers);
  idx++;

  // projections
  c->lin->off[idx] = pp->off[LAB_PROJ];
  polxvec_init(c->lin->phi[idx], pp->len[LAB_PROJ], 1);

  for(i=0;i<LIFTS;i++){
    polxvec_init_subvec2(chalx_sv, chalx, i, 1, 1);
    if(i==0){
      polxvec_mul(c->lin->phi[idx], chalx_sv, phi_jl[i]);
    }
    else{
      polxvec_mul_add(c->lin->phi[idx], chalx_sv, phi_jl[i]);
    }
  }
}

static void ldd_addchecks(
  statement ost,
  const lab_params pp,
  const lab_proof pi,
  const int64_t chalz_jl[LIFTS][LIFTS*pp->r],
  polx *chalx_amortize,
  const polxvec chalx_zq,
  const polxvec phi[pp->r],
  const polxvec jlmat_agg[LIFTS],
  const polxvec phi_jl[LIFTS],
  const sparsecnst finalcnst
)
{
  rqcnstset_init(ost->rqcnst, 3, 7);
  zqcnstset_init(ost->zqcnst, LIFTS+4*SIS1_NCOEF, LIFTS+4*SIS1_NCOEF + 1, 0, 1, 0);

  ost->rqcnst->sparse_nchal = 3;
  ost->rqcnst->com_nchal = pp->kappa[0] + 2*pp->kappa[1] + 4*pp->kappa[2];
  ost->zqcnst->sparse_nchal = LIFTS + 4*SIS1_NCOEF;

  quil_resource_trace("checks_lift_begin");
  ps_addcheck_lift_zero_coeff(ost->zqcnst->sparse, pp->off[LAB_LIFT]);
  quil_resource_trace("checks_lift_end");

  quil_resource_trace("checks_commit_begin");
  ldd_addcheck_commit(ost->rqcnst->com, &ost->zqcnst->sparse[LIFTS], pp, pi);
  quil_resource_trace("checks_commit_end");

  quil_resource_trace("checks_amortization_begin");
  lab_addcheck_amortization(ost->rqcnst->com[6], pp->kappa[0], pp->r,
                            pp->nmax, pp->off[LAB_Z], pp->off[LAB_INCOM],
                            pp->fz, pp->bz, pp->fu, pp->bu, chalx_amortize);
  quil_resource_trace("checks_amortization_end");

  quil_resource_trace("checks_quadg_begin");
  lab_addcheck_quadg(ost->rqcnst->sparse[0], pp->r, pp->off[LAB_QUADG], pp->fz,
                     pp->bz, pp->fg, pp->bg, chalx_amortize);
  quil_resource_trace("checks_quadg_end");

  quil_resource_trace("checks_ling_begin");
  ldd_addcheck_ling(ost->rqcnst->sparse[1], pp, chalz_jl, chalx_amortize, 
                    chalx_zq, phi, jlmat_agg);
  quil_resource_trace("checks_ling_end");

  quil_resource_trace("checks_system_begin");
  ldd_addcheck_system(ost->rqcnst->sparse[2], pp, finalcnst, chalx_zq, phi_jl);
  quil_resource_trace("checks_system_end");
}

void ldd_prove(
  lab_proof pi, 
  statement ost, 
  witness owt, 
  const statement ist, 
  const witness iwt, 
  const lab_params pp
)
{
  size_t i, j, k, tpos, projpos, off, liftpos;
  size_t jlbits[pp->r], jlbits_max;
  uint8_t *jlmat1, *jlmat2;
  int32_t proj32[256];
  int64_t proj64[256];
  int64_t bufbits[4*pp->randlen*N], chalz_jl[LIFTS][LIFTS*pp->r];
  poly *sy[pp->r], *sout;
  polx *chalx_amortize;
  polxvec sxl, sxl_jl, sxq[pp->r], sxq_old[ist->r], phi[pp->r];
  polxvec tx, u1x, tgd, U1, u1d, Up, projd, projx, liftx, liftd, Ub, u2x, hd;
  polxvec chalx_zq, U2, u2d, zx;
  polxvec jl_sprod_sx[LIFTS][pp->r], jlmat_agg[LIFTS], phi_jlproj[LIFTS];
  polxvec phi_jlproj_full[LIFTS];
  sparsecnst zqagg[LIFTS], finalcnst;
  timing time;

  timing_start(&time, "Process input witness");

  // View input witness with new split

  sy[0] = iwt->s[0];
  for(i=1;i<pp->r;i++){
    sy[i] = &sy[i-1][pp->n[i-1]];
  }

  // Input witness to polx

  polxvec_init(sxl, pp->nn, 1);
  polxvec_frompolyvec(sxl, sy[0], 1, pp->nn, 0);
  
  off = 0;
  for(i=0;i<pp->r;i++){
    polxvec_setwidths1(sxl, off, 1, pp->n[i], pp->normsq[i]/(pp->n[i]*N));
    polxvec_init_subvec2(sxq[i], sxl, off, 1, pp->n[i]);
    off += pp->n[i];
  }
  off = 0;
  for(i=0;i<ist->r;i++){
    polxvec_init_subvec2(sxq_old[i], sxl, off, 1, ist->n[i]);
    off += ist->n[i];
  }

  timing_end(&time);
  timing_print(&time, 3);

  // Init

  timing_start(&time, "Init output");
  quil_resource_trace("ldd_input_ready");
  
  lab_witness_init(owt, pp);
  lab_proof_init(pi, pp);
  lab_statement_init(ost, ist, pp);
  sout = owt->s[0];
  quil_resource_trace("ldd_output_ready");

  jlbits_max = 0;
  for(i=0;i<pp->r;i++){
    jlbits[i] = ceil(log2(JL_INF_MULT*sqrt(pp->normsq[i])));
    jlbits_max = MAX(jlbits_max, jlbits[i]);
  }

  timing_end(&time);
  timing_print(&time, 3);

  timing_start(&time, "Init comkey");

  lab_comkey_init(pp);
  quil_resource_trace("ldd_comkey_ready");

  timing_end(&time);
  timing_print(&time, 3);

  // Sample outer commitment randomness

  if(pp->randlen > 0){
    randombits64(bufbits, 4 * pp->randlen * N);
    polyvec_fromint64vec(&sout[pp->off[LAB_RAND1]], bufbits, 1, pp->randlen, 1, 
                        NULL);
    polyvec_fromint64vec(&sout[pp->off[LAB_RAND2]], &bufbits[pp->randlen*N], 
                        1, pp->randlen, 1, NULL);
    polyvec_fromint64vec(&sout[pp->off[LAB_RAND3]], &bufbits[2*pp->randlen*N], 
                        1, pp->randlen, 1, NULL);
    polyvec_fromint64vec(&sout[pp->off[LAB_RAND4]], &bufbits[3*pp->randlen*N], 
                        1, pp->randlen, 1, NULL);
  }

  // Inner commitments

  timing_start(&time, "Inner commitments");

  polxvec_init(tx, pp->kappa[0], 1);
  tpos = pp->off[LAB_INCOM];
  for(i=0;i<pp->r;i++){
    commit(tx, sxq[i]);
    polxvec_decompose(&sout[tpos], tx, tx->len, pp->fu, pp->bu);
    tpos += pp->kappa[0] * pp->fu;
  }

  timing_end(&time);
  timing_print(&time, 3);

  // Quadratic garbage

  timing_start(&time, "Quadratic garbage");
  quil_resource_trace("ldd_inner_commitments_ready");

  lab_quadg(&sout[pp->off[LAB_QUADG]], NULL, sxq, pp->r, pp->fg, pp->bg, 0);
  quil_resource_trace("ldd_quadratic_terms_ready");

  timing_end(&time);
  timing_print(&time, 3);

  // Middle commitment u1

  polxvec_init(u1x, pp->kappa[1], 1);
  polxvec_init(tgd, pp->len[LAB_INCOM] + pp->len[LAB_QUADG], 1);
  polxvec_frompolyvec(tgd, &sout[pp->off[LAB_INCOM]], 1, pp->len[LAB_INCOM],
                      WIDTHMOD(pp->bu));
  polxvec_init_subvec(tgd, tgd, pp->len[LAB_INCOM], 1, pp->len[LAB_QUADG]);
  polxvec_frompolyvec(tgd, &sout[pp->off[LAB_QUADG]], 1, tgd->len, 
                      WIDTHMOD(pp->bg));
  polxvec_init_subvec(tgd, tgd, 0, 1, 0);
  commit(u1x, tgd);
  polxvec_bindec(&sout[pp->off[LAB_U1]], u1x, u1x->len, LOGQ);

  // Outer commitment U1

  polxvec_init(U1, pp->kappa[2], 1);
  polxvec_init(u1d, pp->len[LAB_U1] + pp->len[LAB_RAND1], 1);
  polxvec_frompolyvec(u1d, &sout[pp->off[LAB_U1]], 1, pp->len[LAB_U1], 0.5);
  if(pp->len[LAB_RAND1] > 0){
    polxvec_init_subvec(u1d, u1d, pp->len[LAB_U1], 1, pp->len[LAB_RAND1]);
    polxvec_frompolyvec(u1d, &sout[pp->off[LAB_RAND1]], 1, u1d->len, 0.5);
    polxvec_init_subvec(u1d, u1d, 0, 1, 0);
  }
  commit(U1, u1d);
  polxvec_decompose(&sout[pp->off[LAB_OUTCOM]], U1, 1, pp->fu, pp->bu);
  polzvec_frompolxvec(pi->m[0], U1, 0, 1, pp->kappa[2]);
  outcom_clear(*pi->m[0]);

  update_hash_polz(ost->h, pi->m[0], pp->kappa[2]);

  // JL projections

  timing_start(&time, "Compute JL projections");
  quil_resource_trace("ldd_first_outer_commitment_ready");
  
  jl_sample_mat(&jlmat1, &jlmat2, ost->h, pp->nmax);

  polxvec_init(projx, 256/N, 0);
  projpos = pp->off[LAB_PROJ];
  for(i=0;i<pp->r;i++){
    jl_project(proj32, sy[i], pp->n[i], jlmat1, jlmat2);
    for(j=0;j<256;j++){
      proj64[j] = proj32[j];
    }
    polxvec_fromint64vec(projx, proj64, 256/N, 1, 0);
    polxvec_bindec(&sout[projpos], projx, projx->len, jlbits[i]);
    projpos += 256/N * jlbits[i];
  }
  polxvec_init(sxl_jl, pp->len[LAB_PROJ], 1);
  polxvec_frompolyvec(sxl_jl, &sout[pp->off[LAB_PROJ]], 1, sxl_jl->len, 0.5);
  quil_resource_trace("ldd_projections_ready");

  timing_end(&time);
  timing_print(&time, 3);

  // Outer commitment Up

  polxvec_init(Up, pp->kappa[2], 1);
  polxvec_init(projd, pp->len[LAB_PROJ] + pp->len[LAB_RAND2], 1);
  polxvec_frompolyvec(projd, &sout[pp->off[LAB_PROJ]], 1,pp->len[LAB_PROJ],0.5);
  if(pp->len[LAB_RAND2] > 0){
    polxvec_init_subvec(projd, projd, pp->len[LAB_PROJ], 1, pp->len[LAB_RAND2]);
    polxvec_frompolyvec(projd, &sout[pp->off[LAB_RAND2]], 1, projd->len, 0.5);
    polxvec_init_subvec(projd, projd, 0, 1, 0);
  }
  commit(Up, projd);
  polxvec_decompose(&sout[pp->off[LAB_OUTCOM]+pp->fu], Up, 1, pp->fu, pp->bu);
  polzvec_frompolxvec(pi->m[1], Up, 0, 1, pp->kappa[2]);
  outcom_clear(*pi->m[1]);

  update_hash_polz(ost->h, pi->m[1], pp->kappa[2]);
  
  // Collapse projection matrices
  
  timing_start(&time, "Collapse JL");

  ldd_collapse_jl(jlmat_agg, phi_jlproj, pp->nmax, jlbits_max, jlmat1, jlmat2,
                  ost->h);
  quil_resource_trace("ldd_collapsed_projections_ready");

  timing_end(&time);
  timing_print(&time, 3);
  
  // Aggregate Zq constraints

  timing_start(&time, "Zq aggregation");

  ldd_aggregate_zq(zqagg, phi_jlproj_full, phi_jlproj, jlbits, pp, ist,
                   chalz_jl, ost->h);
  quil_resource_trace("ldd_aggregated_scalar_constraints_ready");

  timing_end(&time);
  timing_print(&time, 3);

  // Aggregation workers have already refreshed their disjoint outputs.

  // Collapsed JL matrices times witness

  timing_start(&time, "Collapsed JL matrices times witness");

  for(i=0;i<LIFTS;i++){
    for(j=0;j<pp->r;j++){
      polxvec_init_subvec(jlmat_agg[i], jlmat_agg[i], 0, 1, pp->n[j]);
      polxvec_init(jl_sprod_sx[i][j], 1, 1);
      polxvec_sprod(jl_sprod_sx[i][j], jlmat_agg[i], sxq[j]);
      polxvec_refresh(jl_sprod_sx[i][j]);
    }
    polxvec_init_subvec(jlmat_agg[i], jlmat_agg[i], 0, 1, 0);
  }

  timing_end(&time);
  timing_print(&time, 3);

  // Lift constraints

  timing_start(&time, "Lift constraints");

  polxvec_init(liftx, 1, 1);
  liftpos = pp->off[LAB_LIFT];
  for(i=0;i<LIFTS;i++){
    sparsecnst_eval(liftx, zqagg[i], sxq_old, sxl);
    polxvec_sprod_add(liftx, phi_jlproj_full[i], sxl_jl);

    for(j=0;j<LIFTS;j++){
      for(k=0;k<pp->r;k++){
        polxvec_scale_add(liftx, jl_sprod_sx[j][k], chalz_jl[i][j*pp->r + k]);
      }
    }

    polxvec_bindec(&sout[liftpos], liftx, liftx->len, LOGQ);
    liftpos += LOGQ;
  }

  timing_end(&time);
  timing_print(&time, 3);

  // Outer commitment Ub

  polxvec_init(Ub, pp->kappa[2], 1);
  polxvec_init(liftd, pp->len[LAB_LIFT] + pp->len[LAB_RAND3], 1);
  polxvec_frompolyvec(liftd, &sout[pp->off[LAB_LIFT]], 1,pp->len[LAB_LIFT],0.5);
  if(pp->len[LAB_RAND3] > 0){
    polxvec_init_subvec(liftd, liftd, pp->len[LAB_LIFT], 1, pp->len[LAB_RAND3]);
    polxvec_frompolyvec(liftd, &sout[pp->off[LAB_RAND3]], 1, liftd->len, 0.5);
    polxvec_init_subvec(liftd, liftd, 0, 1, 0);
  }
  commit(Ub, liftd);
  polxvec_decompose(&sout[pp->off[LAB_OUTCOM]+2*pp->fu], Ub, 1, pp->fu, pp->bu);
  polzvec_frompolxvec(pi->m[2], Ub, 0, 1, pp->kappa[2]);
  outcom_clear(*pi->m[2]);

  update_hash_polz(ost->h, pi->m[2], pp->kappa[2]);

  // Aggregate Rq constraints

  timing_start(&time, "Rq aggregation");

  polxvec_init(chalx_zq, LIFTS, 1);
  ldd_aggregate_rq(finalcnst, chalx_zq, pp, ist, zqagg, ost->h);

  timing_end(&time);
  timing_print(&time, 3);

  off = 0;
  for(i=0;i<pp->r;i++){
    polxvec_init_subvec2(phi[i], finalcnst->lin->phi[0], off, 1, pp->n[i]);
    off += pp->n[i];
  }

  // Linear garbage hij

  timing_start(&time, "Linear garbage");

  ldd_ling(&sout[pp->off[LAB_LING]], pp->r, pp->fu, pp->bu, sxq, phi, chalx_zq, 
           jl_sprod_sx, chalz_jl);

  timing_end(&time);
  timing_print(&time, 3);

  // Middle commitment u2

  polxvec_init(u2x, pp->kappa[1], 1);
  polxvec_init(hd, pp->len[LAB_LING], 1);
  polxvec_frompolyvec(hd, &sout[pp->off[LAB_LING]], 1, pp->len[LAB_LING],
                      WIDTHMOD(pp->bu));
  commit(u2x, hd);
  polxvec_bindec(&sout[pp->off[LAB_U2]], u2x, u2x->len, LOGQ);

  // Outer commitment U2

  polxvec_init(U2, pp->kappa[2], 1);
  polxvec_init(u2d, pp->len[LAB_U2] + pp->len[LAB_RAND4], 1);
  polxvec_frompolyvec(u2d, &sout[pp->off[LAB_U2]], 1, pp->len[LAB_U2], 0.5);
  if(pp->len[LAB_RAND4] > 0){
    polxvec_init_subvec(u2d, u2d, pp->len[LAB_U2], 1, pp->len[LAB_RAND4]);
    polxvec_frompolyvec(u2d, &sout[pp->off[LAB_RAND4]], 1, u2d->len, 0.5);
    polxvec_init_subvec(u2d, u2d, 0, 1, 0);
  }
  commit(U2, u2d);
  polxvec_decompose(&sout[pp->off[LAB_OUTCOM]+3*pp->fu], U2, 1, pp->fu, pp->bu);
  polzvec_frompolxvec(pi->m[3], U2, 0, 1, pp->kappa[2]);
  outcom_clear(*pi->m[3]);

  update_hash_polz(ost->h, pi->m[3], pp->kappa[2]);

  // Amortization

  timing_start(&time, "Amortization");

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

  timing_end(&time);
  timing_print(&time, 3);

  // Generate constraints for the verifier's checks

  timing_start(&time, "Add checks");

  ldd_addchecks(ost, pp, pi, chalz_jl, chalx_amortize, chalx_zq, phi, jlmat_agg, 
                phi_jlproj_full, finalcnst);

  timing_end(&time);
  timing_print(&time, 3);

  timing_start(&time, "Free");

  for(i=0;i<LIFTS;i++){
    sparsecnst_free(zqagg[i]);
    polxvec_free(jlmat_agg[i]);
    polxvec_free(phi_jlproj[i]);
    polxvec_free(phi_jlproj_full[i]);
    for(j=0;j<pp->r;j++){
      polxvec_free(jl_sprod_sx[i][j]);
    }
  }
  sparsecnst_free(finalcnst);

  polxvec_free(sxl);
  polxvec_free(sxl_jl);
  polxvec_free(tx);
  polxvec_free(u1x);
  polxvec_free(tgd);
  polxvec_free(U1);
  polxvec_free(u1d);
  polxvec_free(Up);
  polxvec_free(projd);
  polxvec_free(projx);
  polxvec_free(liftx);
  polxvec_free(liftd);
  polxvec_free(Ub);
  polxvec_free(u2x);
  polxvec_free(hd);
  polxvec_free(chalx_zq);
  polxvec_free(U2);
  polxvec_free(u2d);
  polxvec_free(zx);
  free(jlmat1);
  free(chalx_amortize);

  timing_end(&time);
  timing_print(&time, 3);
}

void ldd_reduce(
  statement ost,
  const statement ist, 
  const lab_proof pi,
  const lab_params pp
)
{
  size_t i, jlbits[pp->r], off, jlbits_max;
  uint8_t *jlmat1, *jlmat2;
  int64_t chalz_jl[LIFTS][LIFTS*pp->r];
  polx *chalx_amortize;
  polxvec phi[pp->r], chalx_zq, jlmat_agg[LIFTS], phi_jlproj[LIFTS];
  polxvec phi_jlproj_full[LIFTS];
  sparsecnst zqagg[LIFTS], finalcnst;
  timing time;

  lab_statement_init(ost, ist, pp);
  lab_comkey_init(pp);

  jlbits_max = 0;
  for(i=0;i<pp->r;i++){
    jlbits[i] = ceil(log2(JL_INF_MULT*sqrt(pp->normsq[i])));
    jlbits_max = MAX(jlbits_max, jlbits[i]);
  }

  // Hash first message

  update_hash_polz(ost->h, pi->m[0], pp->kappa[2]);

  // Sample JL matrices

  jl_sample_mat(&jlmat1, &jlmat2, ost->h, pp->nmax);

  // Hash second message

  update_hash_polz(ost->h, pi->m[1], pp->kappa[2]);

  // Collapse projection matrices
  
  timing_start(&time, "Collapse JL");
  quil_resource_trace("reduce_collapse_begin");

  ldd_collapse_jl(jlmat_agg, phi_jlproj, pp->nmax, jlbits_max, jlmat1, jlmat2,
                  ost->h);

  quil_resource_trace("reduce_collapse_end");
  timing_end(&time);
  timing_print(&time, 3);

  // Aggregate Zq constraints

  timing_start(&time, "Zq aggregation");
  quil_resource_trace("reduce_zq_begin");

  ldd_aggregate_zq(zqagg, phi_jlproj_full, phi_jlproj, jlbits, pp, ist,
                   chalz_jl, ost->h);
  // As in the prover, aggregation workers already refreshed each output.

  quil_resource_trace("reduce_zq_end");
  timing_end(&time);
  timing_print(&time, 3);

  // Hash third message

  update_hash_polz(ost->h, pi->m[2], pp->kappa[2]);

  // Aggregate Rq constraints

  timing_start(&time, "Rq aggregation");
  quil_resource_trace("reduce_rq_begin");

  polxvec_init(chalx_zq, LIFTS, 1);
  ldd_aggregate_rq(finalcnst, chalx_zq, pp, ist, zqagg, ost->h);

  quil_resource_trace("reduce_rq_end");
  timing_end(&time);
  timing_print(&time, 3);

  off = 0;
  for(i=0;i<pp->r;i++){
    polxvec_init_subvec2(phi[i], finalcnst->lin->phi[0], off, 1, pp->n[i]);
    off += pp->n[i];
  }

  // Hash fourth message

  update_hash_polz(ost->h, pi->m[3], pp->kappa[2]);

  // Sample challenges for amortization

  chalx_amortize = _aligned_alloc(64, pp->r * sizeof(polx));
  sample_chalx_amortize(chalx_amortize, pp->r, ost->h);

  // Generate constraints for the verifier's checks

  timing_start(&time, "Add checks");
  quil_resource_trace("reduce_checks_begin");

  ldd_addchecks(ost, pp, pi, chalz_jl, chalx_amortize, chalx_zq, phi, jlmat_agg, 
                phi_jlproj_full, finalcnst);

  quil_resource_trace("reduce_checks_end");
  timing_end(&time);
  timing_print(&time, 3);

  timing_start(&time, "Free");
  quil_resource_trace("reduce_free_begin");

  for(i=0;i<LIFTS;i++){
    sparsecnst_free(zqagg[i]);
    polxvec_free(jlmat_agg[i]);
    polxvec_free(phi_jlproj[i]);
    polxvec_free(phi_jlproj_full[i]);
  }
  sparsecnst_free(finalcnst);

  polxvec_free(chalx_zq);
  free(jlmat1);
  free(chalx_amortize);

  quil_resource_trace("reduce_free_end");
  timing_end(&time);
  timing_print(&time, 3);
}
