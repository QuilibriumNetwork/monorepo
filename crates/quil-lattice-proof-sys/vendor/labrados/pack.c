#include "resource_trace.h"
#include <stdio.h>
#include <time.h>
#include "pack.h"
#include "proofsystem.h"
#include "labrador_core.h"
#include "labradoodle.h"
#include "labrador.h"
#include "labrador_tail.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "malloc.h"
#include "timing.h"

void pack_proof_init(pack_proof pi, const pack_params pp){
  memset(pi,0,sizeof(*pi));
  pi->np = pp->np;
  pi->p = pp->np ? _malloc(pi->np * sizeof(lab_proof)) : NULL;
  pi->zkp = pp->zkp != NULL ? _malloc(sizeof(lnp_proof)) : NULL;
  if(pi->p)memset(pi->p,0,pi->np*sizeof(lab_proof));
  if(pi->zkp)memset(pi->zkp,0,sizeof(lnp_proof));
}

void pack_proof_free(pack_proof pi){
  size_t i;
  for(i=0;i<pi->np;i++){
    lab_proof_free(pi->p[i]);
  }
  if(pi->owt->s)witness_free(pi->owt);
  free(pi->p);
  pi->np = 0;
  free(pi->zkp);
  pi->zkp = NULL;
}

void pack_params_gen(
  pack_params pp, 
  size_t *pibits, 
  const statement st, 
  int zk, 
  size_t iwtbits
)
{
  size_t maxnp = 20;
#ifdef QUIL_BENCH_KNOBS
  /* Benchmark-only: cap the total number of reduction rounds (LNP round
   * included) to trade proof size for verifier time. Prover and verifier must
   * use the same value; this is never compiled into node or wallet builds. */
  {
    const char *cap = getenv("QUIL_BENCH_MAX_ROUNDS");
    if(cap && cap[0] >= '1' && cap[0] <= '9') {
      size_t v = (size_t)atoi(cap);
      if(v >= 3 && v < maxnp) maxnp = v;
    }
  }
  /* The last slot is reserved for the tail round the envelope requires. */
  size_t looplimit = maxnp - 1;
  /* Benchmark-only: force at least this many zero-knowledge labradoodle rounds
   * before the LNP round, ignoring the byte-improvement heuristic. */
  size_t min_zk_rounds = 0;
  {
    const char *mz = getenv("QUIL_BENCH_MIN_ZK_ROUNDS");
    if(mz && mz[0] >= '1' && mz[0] <= '9') min_zk_rounds = (size_t)atoi(mz);
  }
#else
  size_t looplimit = maxnp;
  const size_t min_zk_rounds = 0;
#endif
  size_t i, pisize[maxnp+1], wtsize[maxnp+1+1];
  int compressed, tail, iszk, split, global_norm_check, transition, improve;
  int ret;
  double slack_norm_check;
  statement sts[maxnp+1+1];
  lab_params *cpp;

  pp->np = 0;
  pp->p = _malloc((maxnp + 2) * sizeof(lab_params)); /* LNP round may follow a full loop */
  pp->zkp = zk ? _malloc(sizeof(lnp_params)) : NULL;
  pp->zkround = SIZE_MAX;

  // init statement with relevant info from input statement
  statement_init(sts[0], st->r, st->r);
  for(i=0;i<st->r;i++){
    sts[0]->n[i] = st->n[i];
    sts[0]->normsq[i] = st->normsq[i];
    sts[0]->normty[i] = st->normty[i];
  }
  sts[0]->zqcnst->nsigmam1 = st->zqcnst->nsigmam1;
  wtsize[0] = iwtbits;


  // labradoodle
  transition = 0;
  compressed = 1;
  tail = 0;
  iszk = zk;
  split = 1;

  do {

  while(pp->np < looplimit){
    if(!transition){
      global_norm_check = 0;
      slack_norm_check = JL_INF_SLACK;
    }
    else if(iszk){
      global_norm_check = 0;
      slack_norm_check = 2*JL_INF_SLACK;
    }
    else{
      global_norm_check = 1;
      slack_norm_check = JL_L2_SLACK;
    }
    cpp = &pp->p[pp->np];

    ret = lab_params_gen(*cpp, &pisize[pp->np], &wtsize[pp->np+1], sts[pp->np], 
                         compressed, tail, iszk, split, global_norm_check, 
                         slack_norm_check);
    improve= ((double)(pisize[pp->np] + wtsize[pp->np+1])) < 0.9*wtsize[pp->np];


    if(!ret && !improve && iszk && !transition && pp->np < min_zk_rounds) improve = 1;
    if(ret || (!improve && !transition && pp->np > 0 && pp->zkround != pp->np-1)){
      if(!ret){ 
        lab_params_free(*cpp);
      }
      if(pp->np == 0){
        if (zk){
          printf("ERROR: No Labradoodle params found, ZK not possible\n");
          exit(1);
        }
        break;
      }
      if(pp->zkround == pp->np-1){
        printf("ERROR: No Labradoodle round possible after LNP");
        exit(1);
      }
      transition = 1;
      sts[pp->np]->zqcnst->nsigmam1 = 0;
      statement_free(sts[pp->np]);
      lab_params_free(pp->p[pp->np-1]);
      pp->np--;
      continue;
    }

    pp->np++;

    statement_init(sts[pp->np], 5, 5);
    sts[pp->np]->n[0] = (*cpp)->nmax;
    sts[pp->np]->n[1] = (*cpp)->nmax;
    sts[pp->np]->n[2] = (*cpp)->len[LAB_INCOM] + (*cpp)->len[LAB_QUADG] 
                        + (*cpp)->len[LAB_LING] + (*cpp)->len[LAB_OUTCOM];
    sts[pp->np]->n[3] = (*cpp)->len[LAB_BIN];
    sts[pp->np]->n[4] = sts[pp->np]->n[3]; // include sigmam1
    sts[pp->np]->zqcnst->nsigmam1 = 1;
    for(i=0;i<4;i++){
      sts[pp->np]->normsq[i] = (*cpp)->normsq_new[i];
    }
    sts[pp->np]->normsq[4] = sts[pp->np]->normsq[3];
    // Match actual lab_statement_init plus compiled binary conjugation.
    for(i=0;i<5;i++) sts[pp->np]->normty[i] = (i == 3) ? BIN : L2APPROX;

    if(transition){
      break;
    }
  }

  // lnp
  if (iszk) {    
    ret = lnp_params_gen (pp->zkp[0], &pisize[pp->np], &wtsize[pp->np+1], sts[pp->np]);
    if(ret && pp->np < 10){
      continue; // try another labradoodle round
    }
    else if (ret){
      printf("ERROR: No LNP params found, ZK not possible\n");
      exit(1);
    }

    memset (pp->p[pp->np], 0, sizeof(pp->p[pp->np])); // empty lab proof
    pp->zkround = pp->np;
    pp->np++;
    lnp_statement_init (sts[pp->np], sts[pp->np-1], pp->zkp[0]);
    sts[pp->np]->normsq[sts[pp->np]->r] = N * pp->zkp[0]->xbinlen;
    sts[pp->np]->normty[sts[pp->np]->r] = L2APPROX;
    //sts[pp->np]->rqcnst->nsparse = 1;
    //sts[pp->np]->rqcnst->ncom = 4 + 2;
    //sts[pp->np]->zqcnst->nsparse = LIFTS + 1;
    sts[pp->np]->zqcnst->nsigmam1 = 1;
    sts[pp->np]->r += 1;

    iszk = 0;
    transition = 0;
  } else {
    break;
  }
  
  } while (1);


  // labrador
  compressed = 0;
  tail = 0;
  iszk = 0;
  split = 1;
  global_norm_check = 1;
  slack_norm_check = JL_L2_SLACK;
  while(pp->np < looplimit){
    cpp = &pp->p[pp->np];

    ret = lab_params_gen(*cpp, &pisize[pp->np], &wtsize[pp->np+1], sts[pp->np], 
                         compressed, tail, iszk, split, global_norm_check, 
                         slack_norm_check);
    improve= ((double)(pisize[pp->np] + wtsize[pp->np+1])) < 0.9*wtsize[pp->np];

    if(ret || (!improve && pp->np > 0 && !pp->p[pp->np-1]->compressed)){
      if(!ret){ 
        lab_params_free(*cpp);
      }
      break;
    }

    pp->np++;

    statement_init(sts[pp->np], (*cpp)->fz + 1, (*cpp)->fz + 1);
    sts[pp->np]->n[0] = (*cpp)->nmax;
    sts[pp->np]->n[(*cpp)->fz - 1] = (*cpp)->nmax;
    sts[pp->np]->n[(*cpp)->fz] = (*cpp)->len[LAB_INCOM] + (*cpp)->len[LAB_QUADG] 
                                 + (*cpp)->len[LAB_LING];
    for(i=0;i<sts[pp->np]->r;i++){
      sts[pp->np]->normsq[i] = (*cpp)->normsq_new[i];
    }
  }

  // tail
  if(pp->np < maxnp){
    compressed = 0;
    tail = 1;
    iszk = 0;
    split = 1;
    global_norm_check = 0;
    slack_norm_check = 1;
    cpp = &pp->p[pp->np];

    ret = lab_params_gen(*cpp, &pisize[pp->np], &wtsize[pp->np+1], sts[pp->np], 
                          compressed, tail, iszk, split, global_norm_check, 
                          slack_norm_check);
    if(!ret)
      pp->np++;
  }

  *pibits = 0;
  for(i=0;i<pp->np;i++){
    *pibits += pisize[i];
  }
  *pibits += wtsize[pp->np];
  {
    const char *trace = getenv("QUIL_NATIVE_RESOURCE_TRACE");
    if(trace && !strcmp(trace, "1")) {
      for(i=0;i<pp->np;i++)
        fprintf(stderr, "quil_native_pack_round index=%zu kind=%s proof_bits=%zu witness_bits_after=%zu\n", i,
                (pp->zkp != NULL && i == pp->zkround) ? "lnp" : (pp->p[i]->tail ? "tail" : (pp->p[i]->compressed ? "compressed" : "normal")),
                pisize[i], wtsize[i+1]);
      fprintf(stderr, "quil_native_pack_total rounds=%zu proof_bits=%zu final_witness_bits=%zu\n", pp->np, *pibits, wtsize[pp->np]);
      fflush(stderr);
    }
  }

  for(i=0;i<pp->np;i++){
    sts[i]->zqcnst->nsigmam1 = 0;
    statement_free(sts[i]);
  }
  if(pp->np == 0 || !pp->p[pp->np-1]->tail){
    sts[pp->np]->zqcnst->nsigmam1 = 0;
    statement_free(sts[pp->np]);
  }
}

void pack_params_print(const pack_params pp){
  size_t i;
  for(i=0;i<pp->np;i++){
    printf("\n*** Round %2zu ***\n", i+1);
    if(pp->zkp != NULL && i == pp->zkround){
      printf("LNP round\n");
      lnp_params_print(pp->zkp[0]);
    }
    else{
    lab_params_print(pp->p[i]);
    }
  }
  if(pp->np == 0){
    printf("No rounds: direct statement-witness check\n");
  }
}

void pack_params_free(pack_params pp){
  size_t i;
  for(i=0;i<pp->np;i++){
    lab_params_free(pp->p[i]);
  }
  free(pp->p);
  pp->np = 0;
  free (pp->zkp);
  pp->zkp = NULL;
  pp->zkround = 0;
}

static void lab_prove(
  lab_proof pi, 
  statement ost, 
  witness owt, 
  const statement ist,
  const witness iwt, 
  const lab_params pp
)
{
  timing time;
  const char *trace=getenv("QUIL_NATIVE_RESOURCE_TRACE");
  if(trace && !strcmp(trace,"1")) {
    fprintf(stderr,"quil_native_lab_shape compressed=%d tail=%d r_old=%zu r=%zu nn=%zu nmax=%zu\n",
            pp->compressed,pp->tail,pp->r_old,pp->r,pp->nn,pp->nmax);
    fflush(stderr);
  }

  if(pp->compressed){
    timing_start(&time, "Labradoodle Prover");
    ldd_prove(pi, ost, owt, ist, iwt, pp);
    compile_bincnst(ost, owt);
  }
  else if(!pp->tail){
    timing_start(&time, "Labrador Prover");
    ldr_prove(pi, ost, owt, ist, iwt, pp);
  }
  else{
    timing_start(&time, "Labrador Tail Prover");
    ldr_tail_prove(pi, ost, owt, ist, iwt, pp);
  }
  timing_end(&time);
  timing_print(&time, 2);
}

static int lab_reduce(
  statement ost, 
  const statement ist, 
  const lab_proof pi,
  const lab_params pp
)
{
  int ret;
  timing time;

  if(pp->compressed){
    timing_start(&time, "Labradoodle Verifier");
    ldd_reduce(ost, ist, pi, pp);
    compile_bincnst(ost, NULL);
    ret = 0;
  }
  else if(!pp->tail){
    timing_start(&time, "Labrador Verifier");
    ret = ldr_reduce(ost, ist, pi, pp);
  }
  else{
    timing_start(&time, "Labrador Tail Verifier");
    ret = ldr_tail_reduce(ost, ist, pi, pp);
  }
  timing_end(&time);
  timing_print(&time, 2);
  return ret;
}

int pack_prove(
  pack_proof pi,
  const statement ist,
  const witness iwt,
  const pack_params pp
)
{
  size_t i, j, limit;
  statement tst[2];
  witness twt[2];
  timing time;

  pack_proof_init(pi, pp);

  if(pp->np == 0){
    witness_copy(pi->owt, iwt);
    return 0;
  }
  if(pp->np == 1){
    lab_prove(pi->p[0], tst[0], pi->owt, ist, iwt, pp->p[0]);
    statement_free(tst[0]);
    return 0;
  }

  quil_resource_trace("pack_first_lab_begin");
  lab_prove(pi->p[0], tst[0], twt[0], ist, iwt, pp->p[0]);
  quil_resource_trace("pack_first_lab_end");

  j = 0;
  limit = (pp->zkp != NULL) ? pp->zkround : pp->np - 1;
  for(i=1;i<limit;i++){
    lab_prove(pi->p[i], tst[j^1], twt[j^1], tst[j], twt[j], pp->p[i]);
    statement_free(tst[j]);
    witness_free(twt[j]);
    j ^= 1;
  }
  if(pp->zkp != NULL){
    timing_start(&time,"LNP Prover");
    quil_resource_trace("lnp_prove_begin");
    if(lnp_prove(pi->zkp[0], tst[j^1], twt[j^1], tst[j], twt[j], pp->zkp[0])) {
      statement_free(tst[0]);statement_free(tst[1]);
      witness_free(twt[0]);witness_free(twt[1]);
      return 1;
    }
    quil_resource_trace("lnp_prove_end");
    timing_end(&time);
    timing_print(&time, 2);

    compile_bincnst(tst[j^1], twt[j^1]);

    memset (pi->p[i], 0, sizeof(pi->p[i])); // empty lab proof
    statement_free(tst[j]);
    witness_free(twt[j]);
    j ^= 1;
    for(i=pp->zkround+1;i<pp->np-1;i++){
      lab_prove(pi->p[i], tst[j^1], twt[j^1], tst[j], twt[j], pp->p[i]);
      statement_free(tst[j]);
      witness_free(twt[j]);
      j ^= 1;
    }
    if(pp->zkround == pp->np-1){
      witness_copy(pi->owt, twt[j]);
      statement_free(tst[j]);
      witness_free(twt[j]);
      return 0;
    }
  }

  lab_prove(pi->p[pp->np-1], tst[j^1], pi->owt, tst[j], twt[j], pp->p[pp->np-1]);

  statement_free(tst[0]);
  statement_free(tst[1]);
  witness_free(twt[j]);
  return 0;
}

int pack_verify(
  const statement ist, 
  const pack_params pp, 
  const pack_proof pi
)
{
  size_t i, j, limit;
  int ret;
  statement tst[2];
  timing time;

  if(pp->np == 0){
    if(verify(ist, pi->owt)){
      return 1;
    }
    else{
      fprintf(stderr, "pack_verify failed (verification of final witness)\n");
      return 0;
    }
  }

  quil_resource_trace("verify_first_lab_begin");
  ret = lab_reduce(tst[0], ist, pi->p[0], pp->p[0]);
  quil_resource_trace("verify_first_lab_end");

  if(ret){
    fprintf(stderr, "pack_verify failed (reduction round 1)\n");
    return 0;
  }

  j = 0;
  limit = (pp->zkp != NULL) ? pp->zkround : pp->np;
  for(i=1;i<limit;i++){
    quil_resource_trace("verify_middle_lab_begin");
    ret = lab_reduce(tst[j^1], tst[j], pi->p[i], pp->p[i]);
    quil_resource_trace("verify_middle_lab_end");
    statement_free(tst[j]);
    if(ret){
      fprintf(stderr, "pack_verify failed (reduction round %zu)\n", i+1);
      return 0;
    }
    j ^= 1;
  }
  if(pp->zkp != NULL){
    timing_start(&time, "LNP Verifier");
    quil_resource_trace("verify_lnp_begin");
    ret = lnp_reduce(tst[j^1], tst[j], pi->zkp[0], pp->zkp[0]);
    quil_resource_trace("verify_lnp_end");
    timing_end(&time);
    timing_print(&time, 2);

    compile_bincnst(tst[j^1], NULL);

    statement_free(tst[j]);
    if(ret){
      fprintf(stderr, "pack_verify failed (reduction round %zu)\n", i+1);
      return 0;
    }
    j ^= 1;
    for(i=pp->zkround+1;i<pp->np;i++){
      quil_resource_trace("verify_tail_lab_begin");
      ret = lab_reduce(tst[j^1], tst[j], pi->p[i], pp->p[i]);
      quil_resource_trace("verify_tail_lab_end");
      statement_free(tst[j]);
      if(ret){
        fprintf(stderr, "pack_verify failed (reduction round %zu)\n", i+1);
        return 0;
      }
      j ^= 1;
    }
  }

  quil_resource_trace("verify_final_witness_begin");
  if(verify(tst[j], pi->owt)){
    ret = 1;
  }
  else{
    fprintf(stderr, "pack_verify failed (verification of final witness)\n");
    ret = 0;
  }

  quil_resource_trace("verify_final_witness_end");
  statement_free(tst[j]);
  return ret;
}
