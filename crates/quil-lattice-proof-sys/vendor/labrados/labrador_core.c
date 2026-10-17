#include <math.h>
#include <assert.h>
#include "labrador_core.h"
#include "refresh_parallel.h"
#include "polx.h"
#include "proofsystem.h"
#include "comkey.h"
#include "malloc.h"

void lab_proof_init(lab_proof pi, const lab_params pp){
  if(pp->compressed){
    pi->m[0] = _aligned_alloc(64, 4*pp->kappa[2] * sizeof(polz));
    pi->m[1] = &pi->m[0][pp->kappa[2]];
    pi->m[2] = &pi->m[1][pp->kappa[2]];
    pi->m[3] = &pi->m[2][pp->kappa[2]];
  }
  else if(!pp->tail){
    pi->m[0] = _aligned_alloc(64, (2*pp->kappa[1] + LIFTS) * sizeof(polz));
    pi->m[1] = NULL;
    pi->m[2] = &pi->m[0][pp->kappa[1]];
    pi->m[3] = &pi->m[2][LIFTS];
  }
  else{
    pi->m[0] = _aligned_alloc(64, (pp->len[LAB_INCOM] + pp->len[LAB_QUADG]
                              + pp->len[LAB_LIFT] + pp->len[LAB_LING]) 
                              * sizeof(polz));
    pi->m[1] = NULL;
    pi->m[2] = &pi->m[0][pp->len[LAB_INCOM] + pp->len[LAB_QUADG]];
    pi->m[3] = &pi->m[2][pp->len[LAB_LIFT]];
  }
}

void lab_proof_free(lab_proof pi){
  free(pi->m[0]);
}

static void lab_params_init(
  lab_params pp,
  size_t r_old, 
  size_t r, 
  size_t maxr
)
{
  pp->r_old = r_old;
  pp->r = r;
  pp->rr = _malloc((r_old + maxr)*sizeof(size_t) + maxr * sizeof(int64_t));
  pp->n = &pp->rr[r_old];
  pp->normsq = (uint64_t *) &pp->n[maxr];
}

static void lab_params_copy(lab_params out, const lab_params in){
  size_t i;

  out->r_old = in->r_old;
  for(i=0;i<in->r_old;i++){
    out->rr[i] = in->rr[i];
  }
  out->r = in->r;
  for(i=0;i<in->r;i++){
    out->n[i] = in->n[i];
  }
  out->nn = in->nn;
  out->nmax = in->nmax;
  for(i=0;i<3;i++){
    out->kappa[i] = in->kappa[i];
  }
  out->randlen = in->randlen;
  out->bz = in->bz;
  out->bu = in->bu;
  out->bg = in->bg;
  out->fz = in->fz;
  out->fu = in->fu;
  out->fg = in->fg;
  for(i=0;i<in->r;i++){
    out->normsq[i] = in->normsq[i];
  }
  out->normsq_global = in->normsq_global;
  for(i=0;i<4;i++){
    out->normsq_new[i] = in->normsq_new[i];
  }
  for(i=0;i<14;i++){
    out->off[i] = in->off[i];
    out->len[i] = in->len[i];
  }
  out->compressed = in->compressed;
  out->tail = in->tail;
}

static int lab_params_gen_raw(
  lab_params pp,
  size_t *pibits,
  size_t *owtbits,
  const statement st,
  int decompose_z,
  int global_norm_check,
  double slack_norm_check
)
{
  size_t i, j, pos;
  size_t t_pols, g_pols, h_pols;
  double normsq_max, var_z, var_g, std_z1, slack_protocol;
  double bound_kappa[2];
  double norm_checked_z, norm_checked_z0, norm_checked_z1, norm_checked_tgh;
  int secure;

  // Update lengths and norms according to new split

  pos = 0;
  normsq_max = 0;
  pp->nn = 0;
  pp->nmax = 0;
  pp->normsq_global = 0;
  for(i=0;i<st->r;i++){
    for(j=0;j<pp->rr[i];j++){
      pp->normsq[pos] = (st->normsq[i] + pp->rr[i]-1)/pp->rr[i];
      pp->normsq_global += pp->normsq[pos];
      normsq_max = MAX(normsq_max, pp->normsq[pos]);
      pp->nn += pp->n[pos];
      pp->nmax = MAX(pp->nmax, pp->n[pos]);
      pos++;
    }
  }

  if(pp->compressed && sqrt(normsq_max) > JL_INF_MAXNORM){
    return 1;
  }
  if(!pp->compressed && sqrt(pp->normsq_global) > JL_L2_MAXNORM){
    return 2;
  }

  // Decomposition of the amortization Z

  var_z = (pp->normsq_global * PS_TAU * PS_TAU)/(pp->nmax * N);

  decompose_z = decompose_z || ((64 * var_z) > (1 << 26));

  if(decompose_z){
    pp->fz = 2;
    pp->bz = round((log2(12)+log2(var_z))/4);
    pp->bz = MAX(1, pp->bz);

    pp->normsq_new[0] = 1.3 * pp->nmax * N * (1ULL<<(2*pp->bz)) / 12;
    pp->normsq_new[1] = 1.4*(pp->normsq_global*PS_TAU*PS_TAU)/(1ULL<<(2*pp->bz));
  }
  else{
    pp->fz = 1;
    pp->bz = round((log2(12)+log2(var_z))/2);

    pp->normsq_new[0] = 1.3 * pp->normsq_global * PS_TAU * PS_TAU;
  }

  // Uniform decomposition

  if(!pp->tail){
    pp->fu = (LOGQ + pp->bz/2)/pp->bz;
    pp->bu = (LOGQ + pp->fu-1)/pp->fu;
  }
  else{
    pp->fu = 1;
    pp->bu = LOGQ;
  }

  // Quadratic garbage decomposition

  var_g = normsq_max * normsq_max;

  if(!pp->tail){
    pp->bg = pp->bz;
    pp->fg = ceil((log2(12) + log2(var_g)) / (2*pp->bg));
    pp->fg = MAX(1, pp->fg);
  }
  else{
    pp->fg = 1;
    pp->bg = round((log2(12) + log2(var_g))/2);
  }

  g_pols = (pp->r*pp->r + pp->r)/2 * pp->fg;
  h_pols = pp->tail ? 2 * pp->r - 1 : (pp->r*pp->r + pp->r)/2 * pp->fu;

  // Rank inner commitment

  slack_protocol = pp->compressed ? JL_INF_SLACK : JL_L2_SLACK;

  if(global_norm_check){
    pp->kappa[0] = 0;
    secure = 0;
    while(!secure && pp->kappa[0] < 2048/N){
      pp->kappa[0]++;
      t_pols = pp->r * pp->kappa[0] * pp->fu;

      norm_checked_z0 = pp->normsq_new[0] + (pp->fz - 1) * pp->normsq_new[1];

      if(!pp->tail){
        pp->normsq_new[pp->fz] = (1ULL<<(2*pp->bu)) * t_pols;
        pp->normsq_new[pp->fz] += (1ULL<<(2*pp->bg)) * g_pols;
        pp->normsq_new[pp->fz] += (1ULL<<(2*pp->bu)) * h_pols;
        if(pp->compressed){ // outer commitments
          pp->normsq_new[pp->fz] += (1ULL<<(2*pp->bu)) * 4 * pp->fu;
        }
        pp->normsq_new[pp->fz] *= 1.3 * N/12.0;

        norm_checked_z0 += pp->normsq_new[pp->fz];
      }
      if(pp->compressed){ // binary polynomials
        norm_checked_z0 += 4 * pp->randlen * N;     // randomness
        norm_checked_z0 += 2 * (2048/N) * LOGQ * N; // middle commitments
        norm_checked_z0 += 256 * pp->r * LOGQ;      // projections
        norm_checked_z0 += LIFTS * LOGQ * N;        // liftings
      }
      norm_checked_z0 = sqrt(norm_checked_z0) * slack_norm_check;
      norm_checked_z1 = (pp->fz - 1) * norm_checked_z0;
      norm_checked_z = norm_checked_z0 + (1ULL<<(pp->bz)) * norm_checked_z1;

      bound_kappa[0] = MAX(8 * PS_T * norm_checked_z, 2 * norm_checked_z 
                         + 4 * PS_T * sqrt(normsq_max) * slack_protocol);

      secure = sis_secure(pp->kappa[0], bound_kappa[0]);
    }
  }
  else{
    norm_checked_z0 = sqrt(pp->normsq_new[0]) * slack_norm_check;
    norm_checked_z1 = (pp->fz - 1) * sqrt(pp->normsq_new[1]) * slack_norm_check;
    norm_checked_z = norm_checked_z0 + (1ULL<<(pp->bz)) * norm_checked_z1;

    bound_kappa[0] = MAX(8 * PS_T * norm_checked_z, 2 * norm_checked_z 
                         + 4 * PS_T * sqrt(normsq_max) * slack_protocol);
    pp->kappa[0] = 0;
    secure = 0;
    while(!secure && pp->kappa[0] < 2048/N){
      pp->kappa[0]++;
      secure = sis_secure(pp->kappa[0], bound_kappa[0]);
    }
    t_pols = pp->r * pp->kappa[0] * pp->fu;
  }
  if(!secure) return 3;


  // Rank middle commitment

  pp->kappa[1] = 0;
  if(!pp->tail){
    if(global_norm_check){
      norm_checked_tgh = norm_checked_z0;
    }
    else{
      pp->normsq_new[pp->fz] = (1ULL<<(2*pp->bu)) * t_pols;
      pp->normsq_new[pp->fz] += (1ULL<<(2*pp->bg)) * g_pols;
      pp->normsq_new[pp->fz] += (1ULL<<(2*pp->bu)) * h_pols;
      if(pp->compressed){ // outer commitments
        pp->normsq_new[pp->fz] += (1ULL<<(2*pp->bu)) * 4 * pp->fu;
      }
      pp->normsq_new[pp->fz] *= 1.1 * N/12.0;

      norm_checked_tgh = sqrt(pp->normsq_new[pp->fz]) * slack_norm_check;
    }
    bound_kappa[1] = 2 * norm_checked_tgh;
    secure = 0;
    while(!secure && pp->kappa[1] < 2048/N){
      pp->kappa[1]++;
      secure = sis_secure(pp->kappa[1], bound_kappa[1]);
    }
    if(!secure) return 4;
  }

  // Rank outer commitment

  pp->kappa[2] = pp->compressed ? 1 : 0;

  // Compute lengths

  pp->len[LAB_Z] = pp->nmax * pp->fz;
  pp->len[LAB_INCOM] = t_pols;
  pp->len[LAB_QUADG] = g_pols;
  pp->len[LAB_LING] = h_pols;

  if(pp->compressed){
    pp->len[LAB_OUTCOM] = 4 * pp->fu;
    pp->len[LAB_U1] = pp->kappa[1] * LOGQ;
    pp->len[LAB_RAND1] = pp->randlen;
    pp->len[LAB_PROJ] = 0;
    for(i=0;i<pp->r;i++){
      pp->len[LAB_PROJ] += ceil(log2(JL_INF_MULT*sqrt(pp->normsq[i])));
    }
    pp->len[LAB_PROJ] *= 256/N;
    pp->len[LAB_RAND2] = pp->randlen;
    pp->len[LAB_LIFT] = LIFTS * LOGQ;
    pp->len[LAB_RAND3] = pp->randlen;
    pp->len[LAB_U2] = pp->kappa[1] * LOGQ;
    pp->len[LAB_RAND4] = pp->randlen;
    pp->len[LAB_BIN] = pp->len[LAB_U1] + pp->len[LAB_RAND1] + pp->len[LAB_PROJ] 
                       + pp->len[LAB_RAND2] + pp->len[LAB_LIFT] 
                       + pp->len[LAB_RAND3] + pp->len[LAB_U2] 
                       + pp->len[LAB_RAND4];

    pp->normsq_new[pp->fz + 1] = pp->len[LAB_BIN] * N;
  }
  else{
    pp->len[LAB_LIFT] = LIFTS;
    if(!pp->tail){
      pp->len[LAB_U1] = pp->kappa[1];
      pp->len[LAB_U2] = pp->kappa[1];
    }
  }

  // Compute offsets in witness

  pp->off[LAB_Z] = 0;

  if(!pp->tail){
    pp->off[LAB_INCOM] = pp->off[LAB_Z] + pp->len[LAB_Z];
    pp->off[LAB_QUADG] = pp->off[LAB_INCOM] + pp->len[LAB_INCOM];
    pp->off[LAB_LING] = pp->off[LAB_QUADG] + pp->len[LAB_QUADG];

    if(pp->compressed){
      pp->off[LAB_OUTCOM] = pp->off[LAB_LING] + pp->len[LAB_LING];
      pp->off[LAB_U1] = pp->off[LAB_OUTCOM] + pp->len[LAB_OUTCOM];
      pp->off[LAB_RAND1] = pp->off[LAB_U1] + pp->len[LAB_U1];
      pp->off[LAB_PROJ] = pp->off[LAB_RAND1] + pp->len[LAB_RAND1];
      pp->off[LAB_RAND2] = pp->off[LAB_PROJ] + pp->len[LAB_PROJ];
      pp->off[LAB_LIFT] = pp->off[LAB_RAND2] + pp->len[LAB_RAND2];
      pp->off[LAB_RAND3] = pp->off[LAB_LIFT] + pp->len[LAB_LIFT];
      pp->off[LAB_U2] = pp->off[LAB_RAND3] + pp->len[LAB_RAND3];
      pp->off[LAB_RAND4] = pp->off[LAB_U2] + pp->len[LAB_U2];
      pp->off[LAB_BIN] = pp->off[LAB_U1];
    }
  }

  // Compute offsets in proof

  if(!pp->compressed){
    pp->off[LAB_LIFT] = 0;
    if(pp->tail){
      pp->off[LAB_INCOM] = 0;
      pp->off[LAB_QUADG] = pp->off[LAB_INCOM] + pp->len[LAB_INCOM];
      pp->off[LAB_LING] = 0;
    }
    else{
      pp->off[LAB_U1] = pp->off[LAB_U2] = 0;
    }
  }

  // Compute proof size

  *pibits = 0;

  if(pp->compressed){
    *pibits += 4 * pp->kappa[2] * SIS1_NCOEF * LOGQ;
  }
  else{
    *pibits += 256 * ceil(log2(JL_INF_MULT*sqrt(pp->normsq_global)) + 1);
    *pibits += pp->len[LAB_LIFT] * N * LOGQ;

    if(pp->tail){
      *pibits += pp->len[LAB_INCOM] * N * LOGQ;
      *pibits += pp->len[LAB_QUADG] * N * round((log2(12)+log2(var_g))/2);
      *pibits += pp->len[LAB_LING] * N * LOGQ;
    }
    else{
      *pibits += 2 * pp->kappa[1] * N * LOGQ;
    }
  }

  // Compute witness size

  if(decompose_z){
    std_z1 = sqrt(var_z) / (1ULL << pp->bz);
    *owtbits = pp->nmax * N * (pp->bz + (log2(std_z1) + LOGEDIV2));
  }
  else{
    *owtbits = pp->nmax * N * (log2(sqrt(var_z)) + LOGEDIV2);
  }

  if(!pp->tail){
    *owtbits += pp->len[LAB_INCOM] * N * pp->bu;
    *owtbits += pp->len[LAB_QUADG] * N * pp->bg;
    *owtbits += pp->len[LAB_LING] * N * pp->bu;
  }
  if(pp->compressed){
    *owtbits += pp->len[LAB_OUTCOM] * N * pp->bu;
    *owtbits += 2 * pp->len[LAB_BIN] * N; // also accounts for sigmam1
  }

  return 0;
}

/*
  Generates lab_params for a given statement.
  - pibits: estimated proof size
  - owtbits: estimated size of the output witness
  - st: input statement
  - compressed: if 1, then all prover's messages are compressed
  - tail: if 1, then all prover's messages are sent in the clear
  - zk: if 1, then the outer commitments (when compressed == 1) are to be hiding
  - split: if 1, lab_params_gen tries many different splits of the input witness
    and computes the parameters that achieve the smallest output witness. 
    Otherwise, the input witness is not split any further
  - global_norm_check: if 1, lab_params assumes that the verifier will check
    a global norm bound on the output witness rather than individual for each
    witness vector (relevant when recursing)
  - slack_norm_check: lab_params assumes that the verifier will check the norm
    on the output witness with this given slack (relevant when recursing)

  The function returns 1 if no secure parameters are found
*/
int lab_params_gen(
  lab_params outpp,
  size_t *pibits,
  size_t *owtbits,
  const statement st,
  int compressed,
  int tail,
  int zk,
  int split,
  int global_norm_check,
  double slack_norm_check
)
{
  size_t i, j, k, nn, pib, wtb, bestbits, rem, ncandidates, *candidates;
  size_t decompose, maxsplit;
  lab_params *pp, *bestpp, *tmp;
  int ret;

  assert(!compressed || !tail);
  assert(!zk || compressed);

  if(!split){
    lab_params_init(outpp, st->r, st->r, st->r);
    for(i=0;i<st->r;i++){
      outpp->rr[i] = 1;
      outpp->n[i] = st->n[i];
    }
    outpp->compressed = compressed;
    outpp->tail = tail;
    outpp->randlen = zk ? 2048/N : 0;
    ret = lab_params_gen_raw(outpp, pibits, owtbits, st, 1, 
                             global_norm_check, slack_norm_check);
    if(ret){
      lab_params_free(outpp);
    }
    return ret;
  }
  
  nn = 0;
  for(i=0;i<st->r;i++){
    nn += st->n[i];
  }

  maxsplit = compressed ? 150 : 10;
  // candidate lengths for amortization 'z'
  candidates = _malloc(st->r * maxsplit * sizeof(size_t));
  ncandidates = 0;
  for(i=0;i<st->r;i++){
    for(j=1;j<MIN(st->n[i]+1, maxsplit);j++){
      // length after splitting the i-th witness in j parts
      candidates[ncandidates] = (st->n[i] + j-1)/j;
      ncandidates++;
    }
  }
  qsort(candidates, ncandidates, sizeof(size_t), compare_decreasing);

  pp = _malloc(sizeof(lab_params));
  bestpp = _malloc(sizeof(lab_params));
  lab_params_init(*pp, st->r, 0, nn);
  lab_params_init(*bestpp, st->r, 0, nn);

  bestbits = SIZE_MAX;
  for(i=0; i < ncandidates; i++){
    if(i > 0 && candidates[i] == candidates[i-1]) continue;
    
    (*pp)->r = 0;
    for(j=0;j<st->r;j++){
      (*pp)->rr[j] = (st->n[j] + candidates[i]-1)/candidates[i];
      rem = st->n[j] % (*pp)->rr[j];
      for(k=0;k<(*pp)->rr[j];k++){
        (*pp)->n[(*pp)->r] = st->n[j] / (*pp)->rr[j];
        if(rem > 0){
          (*pp)->n[(*pp)->r]++;
          rem--;
        } 
        (*pp)->r++;
      }
    }
    if((*pp)->r > maxsplit){
      break;
    }
    (*pp)->compressed = compressed;
    (*pp)->tail = tail;
    (*pp)->randlen = zk ? 2048/N : 0;
    decompose = compressed;
    ret = lab_params_gen_raw(*pp, &pib, &wtb, st, decompose,
                              global_norm_check, slack_norm_check);

    if(!ret && pib + wtb < bestbits){
      bestbits = pib + wtb;
      *owtbits = wtb;
      *pibits = pib;
      tmp = bestpp;
      bestpp = pp;
      pp = tmp;
    }

  }

  if((*bestpp)->r == 0){
    ret = 1;
  }
  else{
    lab_params_init(outpp, (*bestpp)->r_old, (*bestpp)->r, (*bestpp)->r);
    lab_params_copy(outpp, *bestpp);
    ret = 0;
  }

  lab_params_free(*pp);
  lab_params_free(*bestpp);
  free(pp);
  free(bestpp);
  free(candidates);

  return ret;
}

void lab_params_print(const lab_params pp){
  size_t i;
  printf("Params:\n");

  printf("\tVersion: ");
  if(pp->compressed){
    printf("Compressed\n");
  }
  else if(!pp->tail){
    printf("Normal\n");
  }
  else{
    printf("Tail\n");
  }

  printf("\tr: %zu\n", pp->r);
  printf("\tn: ");
  for(i=0;i<MIN(pp->r, 10);i++){
    printf("%zu",pp->n[i]);
    if(i<pp->r-1) printf(", ");
  }
  printf("\n");
  printf("\tnn: %zu\n", pp->nn);
  printf("\tnmax: %zu\n", pp->nmax);
  printf("\tnormsq: ");
  for(i=0;i<MIN(pp->r, 10);i++){
    printf("%lu",pp->normsq[i]);
    if(i<pp->r-1) printf(", ");
  }
  printf("\n");
  printf("\tnormsq_global: %lu\n", pp->normsq_global);

  printf("\tkappa[0]: %zu\n", pp->kappa[0]);
  if(!pp->tail){
    printf("\tkappa[1]: %zu\n", pp->kappa[1]);
  }
  if(pp->compressed){
    printf("\tkappa[2]: %zu\n", pp->kappa[2]);
    printf("\trandlen: %zu\n", pp->randlen);
  }

  printf("\tbz: %zu\n", pp->bz);
  printf("\tfz: %zu\n", pp->fz);
  if(!pp->tail){
    printf("\tbu: %zu\n", pp->bu);
    printf("\tfu: %zu\n", pp->fu);
    printf("\tbg: %zu\n", pp->bg);
    printf("\tfg: %zu\n", pp->fg);
  }

  printf("\tnormsq_new: ");
  for(i=0;i<pp->fz;i++){
    printf("%lu, ", pp->normsq_new[i]);
  }
  if(!pp->tail){
    printf("%lu, ", pp->normsq_new[pp->fz]);
  }
  if(pp->compressed){
    printf("%lu", pp->normsq_new[pp->fz + 1]);
  }
  printf("\n");
}

void lab_params_free(lab_params pp){
  free(pp->rr);
}

void lab_witness_init(witness owt, const lab_params pp){
  size_t i, nn_out, r, maxr;

  r = pp->fz;                 // Z
  if(!pp->tail) r++;          // t | g | h
  if(pp->compressed) r++;     // binary
  maxr = r;
  if(pp->compressed) maxr++;  // sigmam1 of binary

  witness_init(owt, r, maxr);

  owt->n[0] = pp->nmax;
  if(pp->fz == 2){
    owt->n[1] = pp->nmax;
  }
  if(!pp->tail){
    owt->n[pp->fz] = pp->len[LAB_INCOM]+pp->len[LAB_QUADG]+pp->len[LAB_LING];
  }
  if(pp->compressed){
    owt->n[pp->fz] += pp->len[LAB_OUTCOM];
    owt->n[pp->fz + 1] = pp->len[LAB_BIN];
  }

  nn_out = 0;
  for(i=0;i<r;i++){
    nn_out += owt->n[i];
  }
  if(pp->compressed) nn_out += owt->n[r-1]; // sigmam1 of binary

  owt->s[0] = _aligned_alloc(64, nn_out * sizeof(poly));
  for(i=1;i<owt->r;i++){
    owt->s[i] = &owt->s[i-1][owt->n[i-1]];
  }
}

void lab_statement_init(
  statement ost, 
  const statement ist, 
  const lab_params pp
)
{
  size_t i, r, maxr;

  r = pp->fz;                 // Z
  if(!pp->tail) r++;          // t | g | h
  if(pp->compressed) r++;     // binary
  maxr = r;
  if(pp->compressed) maxr++;  // sigmam1 of binary

  statement_init(ost, r, maxr);

  ost->n[0] = pp->nmax;
  ost->normty[0] = L2APPROX;
  if(pp->fz == 2){
    ost->n[1] = pp->nmax;
    ost->normty[1] = L2APPROX;
  }
  if(!pp->tail){
    ost->n[pp->fz] = pp->len[LAB_INCOM]+pp->len[LAB_QUADG]+pp->len[LAB_LING];
    ost->normty[pp->fz] = L2APPROX;
  }
  if(pp->compressed){
    ost->n[pp->fz] += pp->len[LAB_OUTCOM];
    ost->n[pp->fz + 1] = pp->len[LAB_BIN];
    ost->normty[pp->fz + 1] = BIN;
  }

  for(i=0;i<r;i++){
    ost->normsq[i] = pp->normsq_new[i];
  }

  memcpy(ost->h, ist->h, HASHLEN);
}


void lab_comkey_init(const lab_params pp){
  size_t cklen;

  cklen = pp->nmax;   // inner commitments

  if(!pp->tail){      // middle commitments
    cklen = MAX(cklen, pp->len[LAB_INCOM] + pp->len[LAB_QUADG]);
    cklen = MAX(cklen, pp->len[LAB_LING]);
  }

  if(pp->compressed){ // outer commitments
    cklen = MAX(cklen, pp->len[LAB_U1] + pp->len[LAB_RAND1]);
    cklen = MAX(cklen, pp->len[LAB_PROJ] + pp->len[LAB_RAND2]);
    cklen = MAX(cklen, pp->len[LAB_LIFT] + pp->len[LAB_RAND3]);
    cklen = MAX(cklen, pp->len[LAB_U2] + pp->len[LAB_RAND4]);
  }

  comkey_init(cklen);
}

/*
  When tail == 0, the output gy is the quadratic garbage, i.e., the inner 
  products <sx[i],sx[j]> where sx is made of r witness vectors. Only the upper 
  triangular matrix is computed. The inner products are decomposed into fg parts 
  in base 2**bg.

  When tail == 1, the inner products are instead transformed to polz and stored
  in gz. No decomposition takes place in this case.
*/
void lab_quadg(
  poly *gy,
  polz *gz, 
  const polxvec sx[], 
  size_t r,
  size_t fg,
  size_t bg,
  int tail
)
{
  polxvec gx, sxi, sxj;
  size_t i, j, len, gpos = 0;
  polxvec_init(gx, 1, 1);

  for(i=0;i<r;i++){
    for(j=i;j<r;j++){
      len = MIN(sx[i]->len, sx[j]->len);
      polxvec_init_subvec2(sxi, sx[i], 0, 1, len);
      polxvec_init_subvec2(sxj, sx[j], 0, 1, len);
      polxvec_sprod(gx, sxi, sxj);
      if(tail){
        polzvec_frompolxvec(&gz[gpos], gx, 0, 1, 1);
        polzvec_center(&gz[gpos], 1);
        gpos++;
      }
      else{
        polxvec_decompose(&gy[gpos], gx, 1, fg, bg);
        gpos += fg;
      }
    }
  }
  polxvec_free(gx);
}

/*
  The output hy is the linear garbage, i.e., of the form
  hy[i][i] = <phi[i], sx[i]> and hy[i][j] = (<phi[i], sx[j]> + <phi[j], sx[i]>)
  for i != j, where phi and sx are made of r witness vectors each. Only the 
  upper triangular matrix is computed. The elements are decomposed into fu parts 
  in base 2**bu.
*/
void lab_ling(
  poly *hy,
  const polxvec sx[], 
  const polxvec phi[], 
  size_t r, 
  size_t fu, 
  size_t bu
)
{
  polxvec hx, phi_sv, sx_sv;
  size_t i, j, len, hpos = 0;

  polxvec_init(hx, 1, 1);

  for(i=0;i<r;i++){
    for(j=i;j<r;j++){
      if(i == j){
        polxvec_sprod(hx, phi[i], sx[i]);
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
      }

      polxvec_decompose(&hy[hpos], hx, 1, fu, bu);
      hpos += fu;
    }
  }
  polxvec_free(hx);
}

void lab_addcheck_amortization(
  comcnst c,
  size_t kappa_inner,
  size_t r,
  size_t n,
  size_t z_off,
  size_t t_off,
  size_t fz,
  size_t bz,
  size_t fu,
  size_t bu,
  polx chalx[r]
)
{
  size_t i;
  polxvec powers, phi_sv;

  comcnst_init(c, kappa_inner, fz, 1, 1);
  polxvec_setzero(c->b, 0, 1, c->b->len);

  c->comk_off[0] = 0;
  c->comw_off[0] = z_off;
  c->comw_len[0] = n;

  if(fz == 2){
    c->comk_off[1] = 0;
    c->comw_off[1] = z_off + n;
    c->comw_len[1] = n;
    c->scalar[1] = 1 << bz;
  }

  c->phiw_off[0] = t_off;
  polxvec_init(c->phi[0], r * fu, 1);

  polxvec_init(powers, fu, 1);
  polxvec_powers(powers, 1 << bu, -1, -1);

  for(i=0;i<r;i++){
    polxvec_init_subvec2(phi_sv, c->phi[0], i*fu, 1, fu);
    polxvec_polx_mul(phi_sv, chalx[i], powers);
  }

  polxvec_free(powers);
}

void lab_addcheck_quadg(
  sparsecnst c,
  size_t r,
  size_t g_off,
  size_t fz,
  size_t bz,
  size_t fg,
  size_t bg,
  polx chalx[r]
)
{
  size_t i, j, off;
  polx cprod, cdouble;
  polxvec powers, phi_sv;

  sparsecnst_init(c, 1);

  quadfunc_init(c->quad, (fz == 2) ? 3 : 1, (fz == 2) ? 3 : 1);

  c->quad->rows[0] = 0;
  c->quad->cols[0] = 0;
  polx_monomial(c->quad->coeffs[0], 0, 1);

  if(fz == 2){
    c->quad->rows[1] = 1;
    c->quad->cols[1] = 1;
    polx_monomial(c->quad->coeffs[1], 0, (1<<bz)*(1<<bz));

    c->quad->rows[2] = 0;
    c->quad->cols[2] = 1;
    polx_monomial(c->quad->coeffs[2], 0, 2*(1<<bz));
  }

  linfunc_init(c->lin, 1, 1, 1);

  c->lin->off[0] = g_off;
  polxvec_init(c->lin->phi[0], (r*r + r)/2 * fg, 1);

  polxvec_init(powers, fg, 1);
  polxvec_powers(powers, 1 << bg, -1, -1);

  off = 0;
  for(i=0;i<r;i++){
    polx_mul(cprod, chalx[i], chalx[i]);
    polxvec_init_subvec2(phi_sv, c->lin->phi[0], off, 1, fg);
    polxvec_polx_mul(phi_sv, cprod, powers);
    off += fg;

    polx_scale(cdouble, chalx[i], 2);
    for(j=i+1;j<r;j++){
      polx_mul(cprod, cdouble, chalx[j]);
      polxvec_init_subvec2(phi_sv, c->lin->phi[0], off, 1, fg);
      polxvec_polx_mul(phi_sv, cprod, powers);
      off += fg;
    }
  }
  polxvec_free(powers);
}

void lab_addcheck_ling(
  sparsecnst c,
  size_t r,
  size_t n,
  size_t z_off,
  size_t h_off,
  size_t fz,
  size_t bz,
  size_t fu,
  size_t bu,
  polx chalx[r],
  const polxvec phi[r]
)
{
  size_t i, j, off;
  polx cprod;
  polxvec powers, phi_sv;

  sparsecnst_init(c, 1);
  linfunc_init(c->lin, 1, fz + 1, fz + 1);

  c->lin->off[0] = z_off;
  polxvec_init(c->lin->phi[0], n, 1);
  polxvec_setzero(c->lin->phi[0], 0, 1, c->lin->phi[0]->len);

  for(i=0;i<r;i++){
    polxvec_init_subvec(c->lin->phi[0], c->lin->phi[0], 0, 1, phi[i]->len);
    polxvec_polx_mul_add(c->lin->phi[0], chalx[i], phi[i]);
  }
  polxvec_init_subvec(c->lin->phi[0], c->lin->phi[0], 0, 1, 0);
  quil_polxvec_parallel_refresh(c->lin->phi[0]);

  if(fz == 2){
    c->lin->off[1] = z_off + n;
    polxvec_init(c->lin->phi[1], n, 1);
    polxvec_scale(c->lin->phi[1], c->lin->phi[0], 1<<bz);
  }

  c->lin->off[fz] = h_off;
  polxvec_init(c->lin->phi[fz], (r*r + r)/2 * fu, 1);

  polxvec_init(powers, fu, 1);
  polxvec_powers(powers, 1 << bu, -1, -1);

  off = 0;
  for(i=0;i<r;i++){
    for(j=i;j<r;j++){
      // no need to multiply by 2 the non-diagonal since those hij are already
      // multiplied by 2 when computed
      polx_mul(cprod, chalx[i], chalx[j]);
      polxvec_init_subvec2(phi_sv, c->lin->phi[fz], off, 1, fu);
      polxvec_polx_mul(phi_sv, cprod, powers);
      off += fu;
    }
  }
  polxvec_free(powers);
}

int compare_decreasing(const void *a, const void *b){
  return (*(int*)b - *(int*)a);
}

size_t trimat_idx(size_t i, size_t j, size_t len) {
  return i*len - (i*i+i)/2 + j;
}