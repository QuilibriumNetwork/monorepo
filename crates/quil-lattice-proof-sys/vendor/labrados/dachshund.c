#include "resource_trace.h"
#include "dachshund.h"
#include "pack.h"
#include "malloc.h"
#include "comkey.h"
#include "timing.h"
#include <inttypes.h>

#define ONE ((__int128_t) 1)
#define MAXNINCOM 200

static void dch_params_init(dch_params pp, size_t maxr, size_t nexact){
  pp->nexact = nexact;
  pp->n = _malloc(maxr * (sizeof(size_t) + sizeof(uint64_t) + sizeof(normtype))
                  + 8*nexact*sizeof(size_t) + 4*MAXNINCOM*sizeof(size_t));
  pp->normsq = (uint64_t*) &pp->n[maxr];
  pp->normty = (normtype*) &pp->normsq[maxr];

  if(nexact == 0 && pp->nquad == 0){
    return;
  }

  pp->exact_map = (size_t*) &pp->normty[maxr];
  pp->incom_offw = &pp->exact_map[nexact];
  pp->incom_lenw = &pp->incom_offw[MAXNINCOM];
  pp->kappa_inner = &pp->incom_lenw[MAXNINCOM];
  pp->off_exact = &pp->kappa_inner[MAXNINCOM];
  pp->off_sigma = &pp->off_exact[nexact];
  pp->off_incom = &pp->off_sigma[nexact];
  pp->len_exact_merge = &pp->off_incom[MAXNINCOM];
  pp->idx_exact = &pp->len_exact_merge[nexact];
  pp->idx_exact_merge = &pp->idx_exact[nexact];
  pp->idx_sigma = &pp->idx_exact_merge[nexact];
  pp->nparts_exact_merge = &pp->idx_sigma[nexact];
}

void dch_params_free(dch_params pp){
  free(pp->n);
}

void dch_params_print(const dch_params pp){
  size_t i;
  size_t limit = 10;
  printf("Dachshund params:\n");

  printf("\tr: %zu\n", pp->r);
  printf("\tn: ");
  for(i=0;i<MIN(pp->r, limit);i++){
    printf("%zu",pp->n[i]);
    if(i<pp->r-1) printf(", ");
  }
  printf("\n");
  printf("\tnormsq: ");
  for(i=0;i<MIN(pp->r, limit);i++){
    printf("%lu",pp->normsq[i]);
    if(i<pp->r-1) printf(", ");
  }
  printf("\n");
  printf("\tnormty: ");
  for(i=0;i<MIN(pp->r, limit);i++){
    printf("%d",pp->normty[i]);
    if(i<pp->r-1) printf(", ");
  }
  printf("\n");
  printf("\tnexact: %zu\n", pp->nexact);
  printf("\tnexact_merge: %zu\n", pp->nexact_merge);
  printf("\tnbin_merge: %zu\n", pp->nbin_merge);
  printf("\tnapprox_merge: %zu\n", pp->napprox_merge);
  printf("\texact_map: ");
  for(i=0;i<MIN(pp->nexact_merge, limit);i++){
    printf("%zu", pp->exact_map[i]);
    if(i<pp->nexact_merge-1) printf(", ");
  }
  printf("\n");
  printf("\tnquad: %zu\n", pp->nquad);
  printf("\tquad_sumranks: %zu\n", pp->quad_sumranks);
  printf("\tquad_nterms: %zu\n", pp->quad_nterms);
  printf("\tquad_maxrank: %zu\n", pp->quad_maxrank);
  printf("\tbase_unif: %zu\n", pp->base_unif);
  printf("\tbase_liftings: %zu\n", pp->base_liftings);
  printf("\tbase_quad_left: %zu\n", pp->base_quad_left);
  printf("\tdigits_unif: %zu\n", pp->digits_unif);
  printf("\tdigits_liftings: %zu\n", pp->digits_liftings);
  printf("\tdigits_quad_left: %zu\n", pp->digits_quad_left);
  printf("\tnincom: %zu\n", pp->nincom);
  printf("\tincom_offw: ");
  for(i=0;i<MIN(pp->nincom, limit);i++){
    printf("%zu", pp->incom_offw[i]);
    if(i<pp->nincom-1) printf(", ");
  }
  printf("\n");
  printf("\tincom_lenw: ");
  for(i=0;i<MIN(pp->nincom, limit);i++){
    printf("%zu", pp->incom_lenw[i]);
    if(i<pp->nincom-1) printf(", ");
  }
  printf("\n");
  printf("\tkappa_inner: ");
  for(i=0;i<MIN(pp->nincom, limit);i++){
    printf("%zu", pp->kappa_inner[i]);
    if(i<pp->nincom-1) printf(", ");
  }
  printf("\n");
  printf("\tkappa_middle: %zu\n", pp->kappa_middle);
  printf("\tkappa_outer: %zu\n", pp->kappa_outer);
  printf("\trandlen: %zu\n", pp->randlen);

  if(pp->nexact == 0 && pp->nquad == 0){
    return;
  }

  printf("\toff_exact: ");
  for(i=0;i<MIN(limit, pp->nexact);i++){
    printf("%zu", pp->off_exact[i]);
    if(i<pp->nexact-1) printf(", ");
  }
  printf("\n");
  printf("\toff_liftings: %zu\n", pp->off_liftings);
  printf("\toff_diff: %zu\n", pp->off_diff);
  printf("\toff_sigma: ");
  for(i=0;i<MIN(limit, pp->nexact);i++){
    printf("%zu", pp->off_sigma[i]);
    if(i<pp->nexact-1) printf(", ");
  }
  printf("\n");
  printf("\toff_incom: ");
  for(i=0;i<MIN(limit, pp->nincom);i++){
    printf("%zu", pp->off_incom[i]);
    if(i<pp->nincom-1) printf(", ");
  }
  printf("\n");
  printf("\toff_midcom: %zu\n", pp->off_midcom);
  printf("\toff_rand: %zu\n", pp->off_rand);
  printf("\toff_quad_left: %zu\n", pp->off_quad_left);
  printf("\toff_quad_right: %zu\n", pp->off_quad_right);
  printf("\tlen_exact_merge: ");
  for(i=0;i<MIN(limit, pp->nexact_merge);i++){
    printf("%zu", pp->len_exact_merge[i]);
    if(i<pp->nexact_merge-1) printf(", ");
  }
  printf("\n");
  printf("\tlen_exact_total: %zu\n", pp->len_exact_total);
  printf("\tlen_bin_total: %zu\n", pp->len_bin_total);
  printf("\tlen_com_inner: %zu\n", pp->len_com_inner);
  printf("\tlen_quad: %zu\n", pp->len_quad);
  printf("\tidx_exact: ");
  for(i=0;i<MIN(limit, pp->nexact);i++){
    printf("%zu", pp->idx_exact[i]);
    if(i<pp->nexact-1) printf(", ");
  }
  printf("\n");
  printf("\tidx_exact_merge: ");
  for(i=0;i<MIN(limit, pp->nexact_merge);i++){
    printf("%zu", pp->idx_exact_merge[i]);
    if(i<pp->nexact_merge-1) printf(", ");
  }
  printf("\n");
  printf("\tidx_sigma: ");
  for(i=0;i<MIN(limit, pp->nexact_merge);i++){
    printf("%zu", pp->idx_sigma[i]);
    if(i<pp->nexact_merge-1) printf(", ");
  }
  printf("\n");
  printf("\tidx_quad: %zu\n", pp->idx_quad);
  printf("\tnparts_exact_merge: ");
  for(i=0;i<MIN(limit, pp->nexact_merge);i++){
    printf("%zu", pp->nparts_exact_merge[i]);
    if(i<pp->nexact_merge-1) printf(", ");
  }
  printf("\n");
  printf("\tnparts_quad: %zu\n", pp->nparts_quad);
}

typedef struct _chunk {
  size_t len;
  size_t nparts;
  size_t idx_part;
} _chunk;

typedef struct _part {
  size_t len;
  uint64_t normsq;
  normtype normty;
} _part;

static int dch_params_split(
  size_t *r,
  size_t *n,
  uint64_t *normsq,
  normtype *normty,
  size_t *nbin,
  size_t *idx_exact_merge,
  size_t *idx_sigma,
  size_t *nparts_exact_merge,
  size_t *nparts_quad,
  size_t candidate,
  size_t nchunks,
  _chunk *chunks,
  _part *parts,
  size_t nexact_merge,
  size_t idx_chunk_quad
)
{
  size_t i, j, nvec, rem, idx_part, len, len_vec, len_part, idx_exact;
  normtype normty_vec;

  *r = 0;
  *nbin = 0;
  idx_exact = 0;
  for(i=0;i<nchunks;i++){
    nvec = (chunks[i].len + candidate-1)/candidate;
    rem = chunks[i].len % nvec;
    idx_part = chunks[i].idx_part;
    len_part = parts[idx_part].len;
    if(parts[idx_part].normty == BIN){
      normty_vec = BIN;
      *nbin += nvec;
    }
    else if(parts[idx_part].normty == L2EXACT){
      normty_vec = L2APPROX;
      if(idx_exact < nexact_merge){
        idx_exact_merge[idx_exact] = *r;
        nparts_exact_merge[idx_exact] = nvec;
      }
      else{
        idx_sigma[idx_exact - nexact_merge] = *r;
      }
      idx_exact++;
    }
    else{
      normty_vec = L2APPROX;
    }
    if(i == idx_chunk_quad){
      *nparts_quad = nvec;
    }
    for(j=0;j<nvec;j++){
      if(*r + *nbin >= DCH_MAXPARTS){
        return 1;
      }
      n[*r] = chunks[i].len / nvec;
      if(rem > 0){
        n[*r]++;
        rem--;
      }
      normty[*r] = normty_vec;
      normsq[*r] = 0;
      len_vec = n[*r];
      while(len_vec > 0){
        if(len_part == 0){
          idx_part++;
          len_part = parts[idx_part].len;
        }

        len = MIN(len_vec, len_part);
        normsq[*r] += parts[idx_part].normsq * (((double) len)/len_part);
        len_vec -= len;
        len_part -= len;
      }
      (*r)++;
    }
  }
  return 0;
}

int dch_params_gen(
  dch_params pp, 
  size_t *pibits, 
  size_t *owtbits,
  const statement st, 
  int zk
)
{
  size_t i, j, k, idx_exact, idx_exact_merge, nexact, off, len, nchunks, nparts;
  size_t *candidates, ncandidates, bestbits, r_split, bestsplit, nn, rank;
  size_t idx_approx, napprox, *approx_nparts, normsq_req, len_total, idx_part;
  size_t owtbits_lab, pibits_lab, maxbinlen, quad1, quad2, bits_quad_left;
  uint64_t normsq, normsq_max;
  polz quadcoefz;
  int secure;
  double bound_sis, var_unif, var_liftings, std, normsq_ensured, var, var_max;
  double *var_quad, base_power, quadcoef_sq;
  statement st_lab;
  lab_params pp_lab;
  _chunk chunks[DCH_MAXPARTS];
  _part *parts;

  // Optional exact/quadratic branches do not assign every field. In
  // particular len_exact_total is consumed by statement construction even
  // when both branches are absent. Never inherit sizes from stack contents.
  memset(pp,0,sizeof(*pp));

  nn = 0;
  nexact = 0;
  napprox = 0;
  normsq_max = 0;
  for(i=0;i<st->r;i++){
    nn += st->n[i];
    if(st->normty[i] == L2EXACT){
      nexact++;
      normsq_max = MAX(normsq_max, st->normsq[i]);
    }
    else if(st->normty[i] == L2APPROX){
      napprox++;
    }
  }

  // Preprocess quadratics

  pp->nquad = 0;
  pp->quad_sumranks = 0;
  pp->quad_nterms = 0;
  pp->quad_maxrank = 0;
  for(i=0;i<st->rqcnst->nsparse;i++){
    if(st->rqcnst->sparse[i]->quad->len > 0){
      pp->nquad++;
      pp->quad_sumranks += st->rqcnst->sparse[i]->b->len;
      pp->quad_nterms += st->rqcnst->sparse[i]->quad->len;
      pp->quad_maxrank = MAX(pp->quad_maxrank, st->rqcnst->sparse[i]->b->len);
    }
  }

  var_quad = pp->nquad > 0 ? _malloc(pp->quad_nterms * sizeof(double)) : NULL;

  pp->len_quad = 0;
  var_max = 0;
  off = 0;
  for(i=0;i<st->rqcnst->nsparse;i++){
    if(st->rqcnst->sparse[i]->quad->len == 0) continue;

    rank = st->rqcnst->sparse[i]->b->len;
    for(j=0;j<st->rqcnst->sparse[i]->quad->len;j++){
      quad1 = st->rqcnst->sparse[i]->quad->rows[j];
      polz_frompolx(quadcoefz, st->rqcnst->sparse[i]->quad->coeffs[j]);
      quadcoef_sq = polzvec_norm(&quadcoefz, 1);
      quadcoef_sq *= quadcoef_sq;

      pp->len_quad += st->n[quad1];
      var = st->normsq[quad1] * PS_TAU * PS_TAU * rank / (st->n[quad1] * N);
      var_quad[off] = var * quadcoef_sq;
      var_max = MAX(var_max, var_quad[off]);
      off++;
    }
  }

  if(pp->nquad > 0){
    bits_quad_left = ceil(log2(8*sqrt(var_max))) + 1;
    pp->digits_quad_left = 1;
    pp->base_quad_left = bits_quad_left;
    while(pp->base_quad_left > 13){
      pp->digits_quad_left++;
      pp->base_quad_left = ceil(bits_quad_left / pp->digits_quad_left);
    }
  }
  else{
    pp->digits_quad_left = pp->base_quad_left = 0;
  }

  dch_params_init(pp, DCH_MAXPARTS, nexact);

  pp->nincom = 0;

  if(pp->nexact > 0){
    nexact = 0;
    off = 0;
    for(i=0;i<st->r;i++){
      if(st->normty[i] == L2EXACT){
        pp->off_exact[nexact] = off;
        pp->idx_exact[nexact] = i;
        nexact++;
      }
      off += st->n[i];
    }
  }

  // Merge exact vectors

  i = 0;
  pp->nexact_merge = 0;
  while(i<pp->nexact){
    idx_exact = pp->idx_exact[i];
    if(st->normsq[idx_exact] > DCH_MAXNORMSQ){
      fprintf(stderr, "ERROR in dachshund parameter generation: norm of vector"  
                      " %zu is too large to be proven exactly"
                      " (%" PRId64 " > %.0f)\n", idx_exact, st->normsq[idx_exact],
                      DCH_MAXNORMSQ);
      dch_params_free(pp);
      free(var_quad);
      return 1;      
    }

    pp->incom_offw[pp->nincom] = pp->off_exact[i];
    pp->exact_map[pp->nexact_merge] = i;
    normsq = st->normsq[idx_exact];
    len = st->n[idx_exact];

    i++;
    while(i<pp->nexact && (pp->idx_exact[i] == pp->idx_exact[i-1] + 1)){
      idx_exact = pp->idx_exact[i];
      normsq += st->normsq[idx_exact];
      len += st->n[idx_exact];
      if(normsq <= DCH_MAXNORMSQ && len <= DCH_MAXLEN){
        i++;
      }
      else{
        normsq -= st->normsq[idx_exact];
        len -= st->n[idx_exact];
        break;
      }
    }
    pp->len_exact_merge[pp->nexact_merge] = len;

    pp->incom_lenw[pp->nincom] = len;
    pp->kappa_inner[pp->nincom] = 0;

    bound_sis = 2 * sqrt(normsq);
    secure = 0;
    while(!secure && pp->kappa_inner[pp->nincom] < 2048/N){
      pp->kappa_inner[pp->nincom]++;
      secure = sis_secure(pp->kappa_inner[pp->nincom], bound_sis);
    }
    if(!secure){
      fprintf(stderr, "ERROR in dachshund parameter generation: no secure "
                      "commitment rank was found to commit to the exact vectors\n");
      dch_params_free(pp);
      free(var_quad);
      return 2;
    }

    pp->nexact_merge++;
    pp->nincom++;
    if(pp->nincom == MAXNINCOM){
      fprintf(stderr, "ERROR in dachshund parameter generation: too many "
                      "inner commitments\n");
      dch_params_free(pp);
      free(var_quad);
      return 20;
    }
  }

  // Merge approx vectors

  approx_nparts = napprox > 0 ? _malloc(napprox * sizeof(size_t)) : NULL;

  i = 0;
  off = 0;
  pp->napprox_merge = 0;
  while(i<st->r){
    if(st->normty[i] != L2APPROX){
      off += st->n[i];
      i++;
      continue;
    }

    normsq_req = st->normsq_req[i];
    normsq_ensured = st->normsq[i] * JL_INF_SLACK * JL_INF_SLACK;
    if(normsq_req < normsq_ensured){
      fprintf(stderr, "ERROR in dachshund parameter generation: norm "
                      "requirement of vector %zu cannot be guaranteed with "
                      "an approximate proof\n", i);
      dch_params_free(pp);
      free(approx_nparts);
      free(var_quad);
      return 3;
    }
  
    len = st->n[i];
    approx_nparts[pp->napprox_merge] = 1;
    i++;

    while(i<st->r && st->normty[i] == L2APPROX){
      normsq_req = MIN(normsq_req, st->normsq_req[i]);
      normsq_ensured += st->normsq[i] * JL_INF_SLACK * JL_INF_SLACK;
      len += st->n[i];

      if(normsq_req < normsq_ensured || len > DCH_MAXLEN){
        normsq_ensured -= st->normsq[i] * JL_INF_SLACK * JL_INF_SLACK;
        len -= st->n[i];
        break;
      }

      approx_nparts[pp->napprox_merge]++;
      i++;
    }

    if(pp->nquad > 0){
      pp->incom_offw[pp->nincom] = off;
      pp->incom_lenw[pp->nincom] = len;
      pp->kappa_inner[pp->nincom] = 0;
      bound_sis = 2 * sqrt(normsq_ensured);
      secure = 0;
      while(!secure && pp->kappa_inner[pp->nincom] < 2048/N){
        pp->kappa_inner[pp->nincom]++;
        secure = sis_secure(pp->kappa_inner[pp->nincom], bound_sis);
      }
      if(!secure){
        fprintf(stderr, "ERROR in dachshund parameter generation: no secure "
                        "commitment rank was found to commit to the approx vectors\n");
        dch_params_free(pp);
        free(approx_nparts);
        free(var_quad);
        return 4;
      }
      pp->nincom++;
      if(pp->nincom == MAXNINCOM){
        fprintf(stderr, "ERROR in dachshund parameter generation: too many "
                        "inner commitments\n");
        dch_params_free(pp);
        free(approx_nparts);
        free(var_quad);
        return 20;
      }
    }

    pp->napprox_merge++;
    off += len;
  }

  // Commitments to binary vectors

  if(pp->nquad > 0){
    off = 0;
    i = 0;
    while(i<st->r){
      if(st->normty[i] != BIN){
        off += st->n[i];
        i++;
        continue;
      }

      len = st->n[i];
      i++;
      while(i<st->r && st->normty[i] == BIN && (len + st->n[i] <= DCH_MAXLEN)){
        len += st->n[i];
        i++;
      }
      
      pp->incom_offw[pp->nincom] = off;
      pp->incom_lenw[pp->nincom] = len;
      pp->kappa_inner[pp->nincom] = 1;
      pp->nincom++;
      off += len;

      if(pp->nincom == MAXNINCOM){
        fprintf(stderr, "ERROR in dachshund parameter generation: too many "
                        "inner commitments\n");
        dch_params_free(pp);
        free(var_quad);
        return 20;
      }
    }
  }

  pp->randlen = zk ? 2048/N : 0;

  pp->digits_unif = 1;
  pp->base_unif = LOGQ;
  while(pp->base_unif > 10){
    pp->digits_unif++;
    pp->base_unif = (LOGQ + pp->digits_unif - 1) / pp->digits_unif;
  }
  var_unif = 1.2 * (1ULL<<(2*pp->base_unif)) / 12.0;

  if(pp->nexact > 0){
    pp->base_liftings = pp->base_unif;
    // the max std of the coefficients of the liftings is normsq_max
    pp->digits_liftings = ceil((log2(12) + 2*log2(normsq_max))
                                / (2*pp->base_liftings));
    pp->digits_liftings = MAX(1, pp->digits_liftings);
    var_liftings = 1.2 * (1ULL<<(2*pp->base_liftings)) / 12.0;
  }
  else{
    pp->base_liftings = pp->digits_liftings = var_liftings = 0;
  }

  // Rank commitment liftings

  if(pp->nexact > 0){
    off = nn;
    len_total = pp->nexact * pp->digits_liftings;
    while(len_total > 0){
      len = MIN(len_total, DCH_MAXLEN);
      pp->incom_offw[pp->nincom] = off;
      pp->incom_lenw[pp->nincom] = len;
      pp->kappa_inner[pp->nincom] = 0;
      normsq = len * N * var_liftings;
      bound_sis = 2 * sqrt(normsq) * JL_INF_SLACK;
      secure = 0;
      while(!secure && pp->kappa_inner[pp->nincom] < 2048/N){
        pp->kappa_inner[pp->nincom]++;
        secure = sis_secure(pp->kappa_inner[pp->nincom], bound_sis);
      }
      if(!secure){
        fprintf(stderr, "ERROR in dachshund parameter generation: no secure "
                        "commitment rank was found to commit to the liftings\n");
        dch_params_free(pp);
        free(approx_nparts);
        free(var_quad);
        return 5;
      }
      pp->nincom++;
      off += len;
      len_total -= len;

      if(pp->nincom == MAXNINCOM){
        fprintf(stderr, "ERROR in dachshund parameter generation: too many "
                        "inner commitments\n");
        dch_params_free(pp);
        free(var_quad);
        return 20;
      }
    }
  }

  // Rank commitment norm differences
  if(pp->nexact > 0){
    off = pp->incom_offw[pp->nincom-1] + pp->incom_lenw[pp->nincom-1];
    len_total = pp->nexact * 256/N;
    while(len_total > 0){
      len = MIN(len_total, DCH_MAXLEN);
      pp->incom_offw[pp->nincom] = off;
      pp->incom_lenw[pp->nincom] = len;
      pp->kappa_inner[pp->nincom] = 1;
      pp->nincom++;
      off += len;
      len_total -= len;

      if(pp->nincom == MAXNINCOM){
        fprintf(stderr, "ERROR in dachshund parameter generation: too many "
                        "inner commitments\n");
        dch_params_free(pp);
        free(var_quad);
        return 20;
      }
    }
  }

  // Rank middle commitment

  pp->kappa_middle = 0;
  if(pp->nexact > 0 || pp->nquad > 0){
    pp->len_com_inner = 0;
    for(i=0;i<pp->nincom;i++){
      pp->len_com_inner += pp->kappa_inner[i];
    }
    pp->len_com_inner *= pp->digits_unif;

    normsq = pp->len_com_inner  * N * var_unif;
    bound_sis = 2 * sqrt(normsq) * JL_INF_SLACK;
    secure = 0;
    while(!secure && pp->kappa_middle < 2048/N){
      pp->kappa_middle++;
      secure = sis_secure(pp->kappa_middle, bound_sis);
    }
    if(!secure){
      dch_params_free(pp);
      free(approx_nparts);
      free(var_quad);
      return 6;
    }
  }

  // Rank outer commitment

  pp->kappa_outer = (pp->nexact > 0 || pp->nquad > 0) ? 1 : 0;

  // Compute offsets

  off = nn;

  if(pp->nexact > 0){
    pp->off_liftings = off;
    off += pp->nexact * pp->digits_liftings;
    pp->off_diff = off;
    off += pp->nexact;
  }

  if(pp->nexact > 0 || pp->nquad > 0){
    pp->off_midcom = off;
    off += pp->kappa_middle * LOGQ;
    pp->off_rand = off;
    off += pp->randlen;
    for(i=0;i<pp->nincom;i++){
      pp->off_incom[i] = off;
      off += pp->kappa_inner[i] * pp->digits_unif;
    }
    for(i=0;i<pp->nexact;i++){
      idx_exact = pp->idx_exact[i];
      pp->off_sigma[i] = off;
      off += st->n[idx_exact];
    }
    pp->len_exact_total = pp->nexact > 0 ? off - pp->off_sigma[0] : 0;
    pp->off_quad_left = off;
    off += pp->len_quad * pp->digits_quad_left;
    pp->off_quad_right = off;
  }

  // Compute parts and chunks info

  parts = _malloc((st->r + 5 + pp->nexact) * sizeof(_part) +
                  pp->quad_nterms * (pp->digits_quad_left+1) * sizeof(_part));

  for(i=0;i<st->r;i++){
    parts[i].len = st->n[i];
    parts[i].normsq = st->normsq[i];
    parts[i].normty = st->normty[i];
  }

  nchunks = 0;
  nparts = 0;
  idx_exact = 0;
  idx_approx = 0;
  while(nparts < st->r){
    chunks[nchunks].idx_part = nparts;
    chunks[nchunks].len = parts[nparts].len;
    chunks[nchunks].nparts = 1;

    if(parts[nparts].normty == L2APPROX){
      nparts++;
      while(nparts < st->r && parts[nparts].normty == L2APPROX &&
            chunks[nchunks].nparts < approx_nparts[idx_approx])
      {
        chunks[nchunks].len += parts[nparts].len;
        chunks[nchunks].nparts++;
        nparts++;
      }
      idx_approx++;
    }
    else if(parts[nparts].normty == BIN){
      nparts++;
      while(nparts < st->r && parts[nparts].normty == BIN){
        chunks[nchunks].len += parts[nparts].len;
        chunks[nchunks].nparts++;
        nparts++;
      }
    }
    else{
      nparts++;
      while(nparts < st->r && parts[nparts].normty == L2EXACT &&
            (idx_exact + 1 == pp->nexact_merge ||
             nparts != pp->idx_exact[pp->exact_map[idx_exact+1]]))
      {
        chunks[nchunks].len += parts[nparts].len;
        chunks[nchunks].nparts++;
        nparts++;
      }
      idx_exact++;
    }
    nchunks++;

    if(nchunks == DCH_MAXPARTS && nparts < st->r){
      fprintf(stderr, "ERROR in dachshund parameter generation: too many "
                      "individual witness parts to be handled by Labrador\n");
      dch_params_free(pp);
      free(parts);
      free(approx_nparts);
      free(var_quad);
      return 7;
    }
  }

  if(pp->nexact > 0){
    if(nchunks + 3 + pp->nexact_merge > DCH_MAXPARTS){
      fprintf(stderr, "ERROR in dachshund parameter generation: too many "
                      "individual witness parts to be handled by Labrador\n");
      dch_params_free(pp);
      free(parts);
      free(approx_nparts);
      free(var_quad);
      return 8;
    }

    // liftings
    parts[nparts].len = pp->nexact * pp->digits_liftings;
    parts[nparts].normsq = parts[nparts].len *  N * var_liftings;
    parts[nparts].normty = L2APPROX;
    chunks[nchunks].idx_part = nparts;
    chunks[nchunks].len = parts[nparts].len;
    chunks[nchunks].nparts = 1;
    nparts++;
    nchunks++;

    // norm differences
    parts[nparts].len = pp->nexact;
    parts[nparts].normsq = parts[nparts].len * N;
    parts[nparts].normty = BIN;
    chunks[nchunks].idx_part = nparts;
    chunks[nchunks].len = parts[nparts].len;
    chunks[nchunks].nparts = 1;
    nparts++;

    // middle commitments (joined with norm differences)
    parts[nparts].len = pp->kappa_middle * LOGQ;
    parts[nparts].normsq = parts[nparts].len * N;
    parts[nparts].normty = BIN;
    chunks[nchunks].len += parts[nparts].len;
    chunks[nchunks].nparts++;
    nparts++;
  }
  else if(pp->nquad > 0){
    if(nchunks + 2 > DCH_MAXPARTS){
      fprintf(stderr, "ERROR in dachshund parameter generation: too many "
                      "individual witness parts to be handled by Labrador\n");
      dch_params_free(pp);
      free(parts);
      free(approx_nparts);
      free(var_quad);
      return 9;
    }

    // middle commitments
    parts[nparts].len = pp->kappa_middle * LOGQ;
    parts[nparts].normsq = parts[nparts].len * N;
    parts[nparts].normty = BIN;
    chunks[nchunks].idx_part = nparts;
    chunks[nchunks].len = parts[nparts].len;
    chunks[nchunks].nparts = 1;
    nparts++;
  }

  if(pp->nexact > 0 || pp->nquad > 0){
    // randomness (joined with middle commitments)
    if(pp->randlen > 0){
      parts[nparts].len = pp->randlen;
      parts[nparts].normsq = parts[nparts].len * N;
      parts[nparts].normty = BIN;
      chunks[nchunks].len += parts[nparts].len;
      chunks[nchunks].nparts++;
      nparts++;
    }
    nchunks++;

    // inner commitments
    parts[nparts].len = pp->len_com_inner;
    parts[nparts].normsq = parts[nparts].len * N * var_unif;
    parts[nparts].normty = L2APPROX;
    chunks[nchunks].idx_part = nparts;
    chunks[nchunks].len = parts[nparts].len;
    chunks[nchunks].nparts = 1;
    nparts++;
    nchunks++;
  }

  if(pp->nexact > 0){
    // sigmam1
    idx_exact_merge = -1;
    for(i=0;i<pp->nexact;i++){
      idx_exact = pp->idx_exact[i];
      parts[nparts].len = st->n[idx_exact];
      parts[nparts].normsq = st->normsq[idx_exact] * PS_T * PS_T;
      parts[nparts].normty = L2EXACT;

      if(idx_exact_merge + 1 < pp->nexact_merge && 
         pp->exact_map[idx_exact_merge + 1] == i)
      {
        idx_exact_merge++;
        if(i > 0){
          nchunks++;
        }
        chunks[nchunks].idx_part = nparts;
        chunks[nchunks].len = parts[nparts].len;
        chunks[nchunks].nparts = 1;
      }
      else{
        chunks[nchunks].len += parts[nparts].len;
        chunks[nchunks].nparts++;
      }
      nparts++;
    }
    nchunks++;
  }

  if(pp->nquad > 0){
    // quad_left and quad_right
    if(nchunks + pp->digits_quad_left + 1 > DCH_MAXPARTS){
      fprintf(stderr, "ERROR in dachshund parameter generation: too many "
                      "individual witness parts to be handled by Labrador\n");
      dch_params_free(pp);
      free(parts);
      free(approx_nparts);
      free(var_quad);
      return 10;
    }

    for(i=0;i<pp->digits_quad_left+1;i++){
      chunks[nchunks].idx_part = nparts + i*pp->quad_nterms;
      chunks[nchunks].len = pp->len_quad;
      chunks[nchunks].nparts = pp->quad_nterms;
      nchunks++;
    }

    base_power = ONE << (2*(pp->digits_quad_left-1)*pp->base_quad_left);
    var = (ONE << (2*pp->base_quad_left))/12;
    off = 0;
    for(i=0;i<st->rqcnst->nsparse;i++){
      len = st->rqcnst->sparse[i]->quad->len;
      if(len == 0) continue;

      for(j=0;j<len;j++){
        quad1 = st->rqcnst->sparse[i]->quad->rows[j];
        quad2 = st->rqcnst->sparse[i]->quad->cols[j];

        // low order digits of quad_left
        for(k=0;k<pp->digits_quad_left-1;k++){
          idx_part = nparts + k * pp->quad_nterms;
          parts[idx_part].len = st->n[quad1];
          parts[idx_part].normsq = 1.3 * var * st->n[quad1] * N;
          parts[idx_part].normty = L2APPROX;
        }

        // most significant digit of quad_left
        idx_part = nparts + (pp->digits_quad_left-1) * pp->quad_nterms;
        parts[idx_part].len = st->n[quad1];
        parts[idx_part].normsq = 1.3 * var_quad[off] * st->n[quad1] * N / base_power;
        parts[idx_part].normty = L2APPROX;

        // quad_right
        idx_part = nparts + pp->digits_quad_left * pp->quad_nterms;
        parts[idx_part].len = st->n[quad2];
        parts[idx_part].normsq = st->normsq[quad2];
        parts[idx_part].normty = L2APPROX;

        nparts++;
        off++;
      }
    }
    nparts += pp->quad_nterms * pp->digits_quad_left;
  }

  *owtbits = 0;
  pp->len_bin_total = 0;
  for(i=0;i<nparts;i++){
    if(parts[i].normty == BIN){
      *owtbits += parts[i].len * N;
      pp->len_bin_total += parts[i].len;
    }
    else{
      std = sqrt(parts[i].normsq / (parts[i].len * N));
      *owtbits += parts[i].len * N * (log2(std) + LOGEDIV2);
    }
  }
  *owtbits += pp->len_bin_total * N; // sigmam1 of binary
  *pibits = (pp->nexact > 0) ? pp->kappa_outer * N * LOGQ : 0;

  statement_init(st_lab, 0, DCH_MAXPARTS);

  candidates = _malloc(nchunks * DCH_MAXPARTS * sizeof(size_t));
  ncandidates = 0;
  for(i=0;i<nchunks;i++){
    for(j=1;j<MIN(chunks[i].len+1, DCH_MAXPARTS);j++){
      candidates[ncandidates] = (chunks[i].len + j-1)/j;
      ncandidates++;
    }
  }
  qsort(candidates, ncandidates, sizeof(size_t), compare_decreasing);

  bestbits = SIZE_MAX;
  bestsplit = 0;
  for(i=0;i<ncandidates;i++){
    if(i>0 && candidates[i] == candidates[i-1]) continue;

    if(dch_params_split(&st_lab->r, st_lab->n, st_lab->normsq, 
                        st_lab->normty, &pp->nbin_merge, pp->idx_exact_merge, 
                        pp->idx_sigma, pp->nparts_exact_merge, &pp->nparts_quad, 
                        candidates[i], nchunks, chunks, parts, pp->nexact_merge,
                        nchunks-1))
    {
      break;
    }

    if(pp->nbin_merge > 0){
      maxbinlen = 0;
      r_split = st_lab->r;
      for(j=0;j<r_split;j++){
        if(st_lab->normty[j] == BIN){
          st_lab->n[st_lab->r] = st_lab->n[j];
          st_lab->normsq[st_lab->r] = st_lab->normsq[j];
          st_lab->normty[st_lab->r] = BIN;
          st_lab->r++;

          maxbinlen = MAX(maxbinlen, st_lab->n[j]);
        }
      }
      if(maxbinlen > PS_MAXBINLEN) continue;
    }

    if(pp->nexact + pp->nbin_merge > 0){
      st_lab->zqcnst->nsigmam1 = 1;
    }

    if(lab_params_gen(pp_lab, &pibits_lab, &owtbits_lab, st_lab, 1, 0, zk, 0, 0,
                      JL_INF_SLACK))
    {
      continue;
    }

    if(owtbits_lab < bestbits){
      bestbits = owtbits_lab;
      bestsplit = candidates[i];
    }

    lab_params_free(pp_lab);
  }
  free(candidates);

  if(bestbits == SIZE_MAX){
    fprintf(stderr, "ERROR in dachshund parameter generation: no valid "
                    "split/merge of the witness was found\n");
    st_lab->zqcnst->nsigmam1 = 0;
    statement_free(st_lab);
    dch_params_free(pp);
    free(parts);
    free(approx_nparts);
    free(var_quad);
    return 11;
  }

  dch_params_split(&pp->r, pp->n, pp->normsq, pp->normty, &pp->nbin_merge,
                   pp->idx_exact_merge, pp->idx_sigma, pp->nparts_exact_merge, 
                   &pp->nparts_quad, bestsplit, nchunks, chunks, parts, 
                   pp->nexact_merge, nchunks-1);
  if(pp->nquad == 0){
    pp->nparts_quad = 0;
    pp->idx_quad = 0;
  }
  else{
    pp->idx_quad = pp->r - pp->nparts_quad * (pp->digits_quad_left+1);
  }

  st_lab->zqcnst->nsigmam1 = 0;
  statement_free(st_lab);
  free(parts);
  free(approx_nparts);
  free(var_quad);
  
  return 0;
}

void dch_proof_free(dch_proof pi){
  if(pi->com != NULL){
    free(pi->com);
  }
}

static void dch_statement_init(
  statement ost,
  const statement ist, 
  const dch_params pp, int borrow_public
)
{
  size_t i, idx_ost, rq_ncom, rq_nsparse, zq_nsparse, zq_nsigma;

  statement_init(ost, pp->r, pp->r + pp->nbin_merge);

  for(i=0;i<pp->r;i++){
    ost->n[i] = pp->n[i];
    ost->normsq[i] = pp->normsq[i];
    ost->normty[i] = pp->normty[i];
  }

  rq_ncom = (pp->nexact > 0 || pp->nquad > 0) ? 2 + pp->nincom : 0;
  rq_nsparse = pp->nexact_merge + 2*pp->len_quad;
  if(pp->nquad > 0){
    rq_nsparse++;
  }
  rqcnstset_init(ost->rqcnst, ist->rqcnst->nsparse + rq_nsparse - pp->nquad,
                 ist->rqcnst->ncom + rq_ncom);
  idx_ost = 0;
  for(i=0;i<ist->rqcnst->nsparse;i++){
    if(ist->rqcnst->sparse[i]->quad->len > 0) continue;

    if(borrow_public) sparsecnst_borrow_public(ost->rqcnst->sparse[idx_ost], ist->rqcnst->sparse[i]);
    else sparsecnst_copy(ost->rqcnst->sparse[idx_ost], ist->rqcnst->sparse[i]);
    idx_ost++;
  }
  for(i=0;i<ist->rqcnst->ncom;i++){
    comcnst_copy(ost->rqcnst->com[i], ist->rqcnst->com[i]);
  }
  ost->rqcnst->sparse_nchal = ist->rqcnst->sparse_nchal + rq_nsparse;
  ost->rqcnst->com_nchal = ist->rqcnst->com_nchal;
  for(i=0;i<pp->nincom;i++){
    ost->rqcnst->com_nchal += pp->kappa_inner[i];
  }
  ost->rqcnst->com_nchal += pp->kappa_middle + pp->kappa_outer;

  zq_nsparse = pp->nexact;
  zq_nsigma = pp->nexact;
  zqcnstset_init(ost->zqcnst, ist->zqcnst->nsparse + zq_nsparse,
                 ist->zqcnst->nsparse + zq_nsparse + pp->nbin_merge,
                 ist->zqcnst->nsigmam1 + zq_nsigma,
                 ist->zqcnst->nsigmam1 + zq_nsigma + pp->nbin_merge,
                 ist->zqcnst->nint);
  for(i=0;i<ist->zqcnst->nsparse;i++){
    if(borrow_public) sparsecnst_borrow_public(ost->zqcnst->sparse[i], ist->zqcnst->sparse[i]);
    else sparsecnst_copy(ost->zqcnst->sparse[i], ist->zqcnst->sparse[i]);
  }
  for(i=0;i<ist->zqcnst->nsigmam1;i++){
    sigmam1cnst_copy(ost->zqcnst->sigmam1[i], ist->zqcnst->sigmam1[i]);
  }
  for(i=0;i<ist->zqcnst->nint;i++){
    intcnst_copy(ost->zqcnst->intc[i], ist->zqcnst->intc[i]);
  }
  ost->zqcnst->sparse_nchal = ist->zqcnst->sparse_nchal + zq_nsparse;
  ost->zqcnst->sigmam1_nchal = ist->zqcnst->sigmam1_nchal + pp->len_exact_total;
  ost->zqcnst->int_nchal = ist->zqcnst->int_nchal;
          
  memcpy(ost->h, ist->h, HASHLEN);
}

static void dch_witness_init(
  witness owt,
  const witness iwt,
  const dch_params pp
)
{
  size_t i, nn;

  witness_init(owt, pp->r, pp->r + pp->nbin_merge);

  nn = 0;
  for(i=0;i<owt->r;i++){
    owt->n[i] = pp->n[i];
    nn += owt->n[i];
  }
  nn += pp->len_bin_total; // sigmam1 of binary vectors

  owt->s[0] = _aligned_alloc(64, nn * sizeof(poly));
  for(i=1;i<owt->r;i++){
    owt->s[i] = &owt->s[i-1][owt->n[i-1]];
  }
  
  nn = 0;
  for(i=0;i<iwt->r;i++){
    nn += iwt->n[i];
  }
  polyvec_copy(owt->s[0], iwt->s[0], 1, 1, nn);
}

static void dch_comkey_init(const dch_params pp){
  size_t i, cklen;

  if(pp->nexact == 0 && pp->nquad == 0){
    comkey_init(1);
    return;
  }

  cklen = 0;
  for(i=0;i<pp->nincom;i++){
    cklen = MAX(cklen, pp->incom_lenw[i]);
  }
  cklen = MAX(cklen, pp->len_com_inner); // middle com
  cklen = MAX(cklen, pp->kappa_middle * LOGQ + pp->randlen); // outer com

  comkey_init(cklen);
}

// todo: merge with orthus.c function
static void sigmapower2(int64_t powers[N], size_t nbits){
  size_t i;

  powers[0] = 1;
  if(nbits > 1){
    powers[N-1] = -2;
  }
  for(i=2;i<nbits;i++){
    powers[N-i] = 2 * powers[N-i+1];
  }
  memset(&powers[1], 0, (N-nbits) * sizeof(int64_t));
}

static void dch_addcheck_commit_inner(
  comcnst c, 
  size_t rank, 
  size_t cpos,
  size_t cdigits,
  size_t cbase,
  size_t wpos, 
  size_t wlen
)
{
  comcnst_init(c, rank, 1, 1, 1);

  c->comk_off[0] = 0;
  c->comw_off[0] = wpos;
  c->comw_len[0] = wlen;

  c->phiw_off[0] = cpos;
  polxvec_init(c->phi[0], cdigits, 1);
  polxvec_powers(c->phi[0], 1<<cbase, -1, -1);

  polxvec_setzero(c->b, 0, 1, rank);
}

static void dch_addcheck_commit(
  comcnst *c,
  const dch_params pp,
  const dch_proof pi
)
{
  size_t i, idx;

  ps_addcheck_commit_in_clear(c[0], pi->com, pp->kappa_outer,pp->off_midcom, 
                              pp->kappa_middle * LOGQ + pp->randlen);
  ps_addcheck_commit_middle(c[1], pp->kappa_middle, pp->off_midcom,
                            pp->off_incom[0], pp->len_com_inner);
  idx = 2;
  for(i=0;i<pp->nincom;i++){
    dch_addcheck_commit_inner(c[idx], pp->kappa_inner[i], pp->off_incom[i],
                              pp->digits_unif, pp->base_unif,
                              pp->incom_offw[i], pp->incom_lenw[i]);
    idx++;
  }
}

static void dch_addcheck_lifts_zero_coeff(sparsecnst *c, const dch_params pp){
  size_t i;
  polxvec powers;

  polxvec_init(powers, pp->digits_liftings, 1);
  polxvec_powers(powers, 1<<pp->base_liftings, 1, 1);

  for(i=0;i<pp->nexact;i++){
    sparsecnst_init(c[i], 1);
    linfunc_init(c[i]->lin, 1, 1, 1);

    c[i]->lin->off[0] = pp->off_liftings + i*pp->digits_liftings;
    polxvec_init(c[i]->lin->phi[0], pp->digits_liftings, 1);
    polxvec_copy(c[i]->lin->phi[0], powers);
  }
  polxvec_free(powers);
}

static void dch_addcheck_norms(
  sparsecnst *c,
  const dch_params pp,
  const statement ist,
  polxvec chalx
)
{
  size_t i, j, start, end, nbits;
  int64_t powers2[N];
  double width;
  polxvec powers;

  polxvec_init(powers, pp->digits_liftings, 1);
  polxvec_powers(powers, 1<<pp->base_liftings, -1, -1);

  for(i=0;i<pp->nexact_merge;i++){
    sparsecnst_init(c[i], 1);
    quadfunc_init(c[i]->quad,pp->nparts_exact_merge[i],pp->nparts_exact_merge[i]);
    for(j=0;j<c[i]->quad->len;j++){
      c[i]->quad->rows[j] = pp->idx_exact_merge[i] + j;
      c[i]->quad->cols[j] = pp->idx_sigma[i] + j;
      polx_monomial(c[i]->quad->coeffs[j], 0, 1);
    }

    start = pp->exact_map[i];
    end = (i != pp->nexact_merge-1) ? pp->exact_map[i+1] : pp->nexact;
    linfunc_init(c[i]->lin, 1, 2*(end-start), 2*(end-start));
    for(j=0;j<end-start;j++){
      polxvec_init_subvec(chalx, chalx, start + j, 1, 1);

      c[i]->lin->off[2*j] = pp->off_diff + start + j;
      polxvec_init(c[i]->lin->phi[2*j], 1, 1);
      nbits = ceil(log2(ist->normsq[pp->idx_exact[start + j]]+1));
      sigmapower2(powers2, nbits);
      width = (ONE << (2*nbits+2))/N;
      polxvec_fromint64vec2(c[i]->lin->phi[2*j], powers2, 1, 1, width);
      polxvec_mul(c[i]->lin->phi[2*j], chalx, c[i]->lin->phi[2*j]);

      c[i]->lin->off[2*j+1] = pp->off_liftings + (start + j)*pp->digits_liftings;
      polxvec_init(c[i]->lin->phi[2*j+1], pp->digits_liftings, 1);
      polxvec_mul(c[i]->lin->phi[2*j+1], chalx, powers);

      polxvec_scale_add(c[i]->b, chalx, ist->normsq[pp->idx_exact[start+j]]);
    }
  }
  polxvec_init_subvec(chalx, chalx, 0, 1, 0);
  polxvec_free(powers);
}

static void dch_addcheck_sigma(
  sigmam1cnst *c,
  const dch_params pp,
  const statement ist,
  polxvec chalx
)
{
  size_t i;
  for(i=0;i<pp->nexact;i++){
    sigmam1cnst_init(c[i], pp->off_exact[i], pp->off_sigma[i], 
                     ist->n[pp->idx_exact[i]], 1);
    polxvec_init_subvec(chalx, chalx, i, 1, 1);
    polxvec_copy(c[i]->c, chalx);
  }
  polxvec_init_subvec(chalx, chalx, 0, 1, 0);
}

static void dch_addcheck_quad_left(
  sparsecnst *c,
  const dch_params pp,
  const statement ist,
  const size_t *off_map,
  polxvec chalx_quad
)
{
  size_t i, j, k, l, m, idx_cnst, idx_left, off_orig, off_new_start, off_new=0;
  size_t rank, off_chal;
  int64_t base, s;
  polxvec chalx_rot, chalx_times_coeff, chalx_sv;
  polx monx;

  base = ONE << pp->base_quad_left;

  polxvec_init(chalx_rot, pp->quad_maxrank, 1);
  polxvec_init(chalx_times_coeff, pp->quad_maxrank, 1);
  polx_monomial(monx, 1, 1);

  idx_cnst = 0;
  off_chal = 0;
  off_new_start = pp->off_quad_left;
  for(i=0;i<ist->rqcnst->nsparse;i++){
    if(ist->rqcnst->sparse[i]->quad->len == 0) continue;
    rank = ist->rqcnst->sparse[i]->b->len;
    polxvec_init_subvec(chalx_times_coeff, chalx_times_coeff, 0, 1, rank);
    for(j=0;j<rank;j++){
      off_new = off_new_start + j;
      polxvec_init_subvec2(chalx_sv, chalx_quad, off_chal+j, 1, rank-j);
      polxvec_init_subvec(chalx_rot, chalx_rot, 0, 1, rank-j);
      polxvec_copy(chalx_rot, chalx_sv);

      if(j > 0){
        polxvec_init_subvec2(chalx_sv, chalx_quad, off_chal, 1, j);
        polxvec_init_subvec(chalx_rot, chalx_rot, rank-j, 1, j);
        polxvec_polx_mul(chalx_rot, monx, chalx_sv);
      }
      polxvec_init_subvec(chalx_rot, chalx_rot, 0, 1, rank);

      for(k=0;k<ist->rqcnst->sparse[i]->quad->len;k++){
        idx_left = ist->rqcnst->sparse[i]->quad->rows[k];
        off_orig = off_map[idx_left];
        polxvec_polx_mul(chalx_times_coeff, 
                         ist->rqcnst->sparse[i]->quad->coeffs[k], chalx_rot);
        for(l=j;l<ist->n[idx_left];l+=rank){
          sparsecnst_init(c[idx_cnst], 1);
          linfunc_init(c[idx_cnst]->lin, 1, pp->digits_quad_left+1, 
                       pp->digits_quad_left+1);
          
          c[idx_cnst]->lin->off[0] = off_orig;
          polxvec_init(c[idx_cnst]->lin->phi[0], rank, 1);
          polxvec_copy(c[idx_cnst]->lin->phi[0], chalx_times_coeff);

          s = 1;
          for(m=1;m<pp->digits_quad_left+1;m++){
            c[idx_cnst]->lin->off[m] = off_new + (m-1)*pp->len_quad;
            polxvec_init(c[idx_cnst]->lin->phi[m], 1, 1);
            polxvec_monomial(c[idx_cnst]->lin->phi[m], 0, 0, -s);
            s *= base;
          }
          idx_cnst++;
          off_orig += rank;
          off_new += rank;
        }

      }
    }
    off_new_start = off_new - rank + 1;
    off_chal += rank;
  }

  polxvec_free(chalx_rot);
  polxvec_free(chalx_times_coeff);
}

static void dch_addcheck_quad_right(
  sparsecnst *c,
  const dch_params pp,
  const statement ist,
  const size_t *off_map
)
{
  size_t i, j, k, idx_cnst, idx_right, off_orig, off_new;

  idx_cnst = 0;
  off_new = pp->off_quad_right;
  for(i=0;i<ist->rqcnst->nsparse;i++){
    if(ist->rqcnst->sparse[i]->quad->len == 0) continue;

    for(j=0;j<ist->rqcnst->sparse[i]->quad->len;j++){
      idx_right = ist->rqcnst->sparse[i]->quad->cols[j];
      off_orig = off_map[idx_right];
      for(k=0;k<ist->n[idx_right];k++){
        sparsecnst_init(c[idx_cnst], 1);
        linfunc_init(c[idx_cnst]->lin, 1, 2, 2);

        c[idx_cnst]->lin->off[0] = off_orig;
        polxvec_init(c[idx_cnst]->lin->phi[0], 1, 1);
        polxvec_monomial(c[idx_cnst]->lin->phi[0], 0, 0, 1);

        c[idx_cnst]->lin->off[1] = off_new;
        polxvec_init(c[idx_cnst]->lin->phi[1], 1, 1);
        polxvec_monomial(c[idx_cnst]->lin->phi[1], 0, 0, -1);

        idx_cnst++;
        off_orig++;
        off_new++;
      }
    }
  }
}

static void dch_addcheck_quadratic(
  sparsecnst c,
  const dch_params pp,
  const statement ist,
  polxvec chalx_quad,
  size_t nn
)
{
  size_t i, j, off_chalx, rank, idx_left, idx_right, nparts_left;
  polxvec chalx_sv, outphi;
  sparsecnst *in;
  int64_t s, base = ONE << pp->base_quad_left;

  nparts_left = pp->digits_quad_left * pp->nparts_quad;

  sparsecnst_init(c, 1);

  quadfunc_init(c->quad, 0, nparts_left);
  
  idx_left = pp->idx_quad;
  s = 1;
  for(i=0;i<pp->digits_quad_left;i++){
    idx_right = pp->idx_quad + nparts_left;

    for(j=0;j<pp->nparts_quad;j++){
      c->quad->rows[c->quad->len] = idx_left;
      c->quad->cols[c->quad->len] = idx_right;
      polx_monomial(c->quad->coeffs[c->quad->len], 0, s);
      c->quad->len++;

      idx_left++;
      idx_right++;
    }
    s *= base;
  }

  linfunc_init(c->lin, 1, 1, 1);
  c->lin->off[0] = 0;
  polxvec_init(c->lin->phi[0], nn, 1);
  polxvec_setzero(c->lin->phi[0], 0, 1, nn);

  off_chalx = 0;
  for(i=0;i<ist->rqcnst->nsparse;i++){
    in = &ist->rqcnst->sparse[i];
    if((*in)->quad->len == 0) continue;

    rank = (*in)->b->len;
    polxvec_init_subvec2(chalx_sv, chalx_quad, off_chalx, 1, rank);

    polxvec_sprod_add(c->b, chalx_sv, (*in)->b);

    for(j=0;j<(*in)->lin->nparts;j++){
      polxvec_init_subvec2(outphi, c->lin->phi[0], (*in)->lin->off[j], 1,
                           (*in)->lin->phi[j]->len);
      if(rank == 1){
        polxvec_mul_add(outphi, chalx_sv, (*in)->lin->phi[j]);
      }
      else{
        polxvec_rotation_aggregate_add(outphi, chalx_sv, (*in)->lin->phi[j]);
      }
    }

    off_chalx += rank;
  }

}

static void dch_addchecks(
  statement ost,
  const dch_params pp,
  const statement ist,
  const dch_proof pi,
  polxvec chalx_exact,
  polxvec chalx_quad,
  const size_t *off_map,
  size_t nn
)
{
  size_t idx_rqsparse = ist->rqcnst->nsparse - pp->nquad;
  dch_addcheck_commit(&ost->rqcnst->com[ist->rqcnst->ncom], pp, pi);
  if(pp->nexact > 0){
    dch_addcheck_lifts_zero_coeff(&ost->zqcnst->sparse[ist->zqcnst->nsparse], pp);
    dch_addcheck_norms(&ost->rqcnst->sparse[idx_rqsparse], 
                       pp, ist, chalx_exact);
    idx_rqsparse += pp->nexact_merge;
    dch_addcheck_sigma(&ost->zqcnst->sigmam1[ist->zqcnst->nsigmam1], pp, ist,
                       chalx_exact);
  }
  if(pp->nquad > 0){
    dch_addcheck_quad_left(&ost->rqcnst->sparse[idx_rqsparse], pp, ist, off_map,
                           chalx_quad);
    idx_rqsparse += pp->len_quad;
    dch_addcheck_quad_right(&ost->rqcnst->sparse[idx_rqsparse], pp, ist, 
                            off_map);
    idx_rqsparse += pp->len_quad;
    dch_addcheck_quadratic(ost->rqcnst->sparse[idx_rqsparse], pp, ist,
                           chalx_quad, nn);
  }
}

static void dch_prove_impl(
  dch_proof pi,
  statement ost, 
  witness owt, 
  const statement ist,
  const witness iwt, 
  const dch_params pp, int borrow_public
)
{
  size_t i, j, k, idx, idx_merge, nbits, off_exact, kappa_max, nn, off, len;
  size_t rank, quad1, quad2, off_chal, *off_map;
  uint64_t normsq;
  int64_t powers64[N], bufbits[pp->randlen*N];
  double width_exact, width_powers;
  poly *sout;
  polz liftz;
  polxvec sigma1d, lift1d, powers, tx, incom, midcom, chalx_exact, chalx_quad;
  polxvec sx, *exact, *exact_merge, *sigma, *diff, *lift, *liftdec;
  polxvec quad_left, quad_agg, chalx_times_coeff;

  dch_comkey_init(pp);
  dch_statement_init(ost, ist, pp, borrow_public);
  dch_witness_init(owt, iwt, pp);
  sout = owt->s[0];

  if(pp->nexact == 0 && pp->nquad == 0){
    pi->com = NULL;
    return;
  }
  pi->com = _aligned_alloc(64, pp->kappa_outer * sizeof(polz));

  off_map = _malloc(ist->r * sizeof(size_t));

  nn = 0;
  for(i=0;i<ist->r;i++){
    off_map[i] = nn;
    nn += ist->n[i];
  }

  polxvec_init(sx, nn + pp->nexact * (pp->digits_liftings + 256/N), 1);

  if(pp->nquad > 0){
    polxvec_frompolyvec(sx, iwt->s[0], 1, nn, 1);
  }

  if(pp->nexact > 0){
    polxvec_init(sigma1d, pp->len_exact_total, 1);
    polxvec_init(lift1d, pp->nexact, 1);
    polxvec_init(powers, 1, 1);

    exact = _malloc((5 * pp->nexact + pp->nexact_merge) * sizeof(polxvec));
    sigma = &exact[pp->nexact];
    diff = &sigma[pp->nexact];
    lift = &diff[pp->nexact];
    liftdec = &lift[pp->nexact];
    exact_merge = &liftdec[pp->nexact];
  }
  else{
    exact = sigma = diff = lift = liftdec = exact_merge = NULL;
  }

  off_exact = 0;
  idx_merge = 0;
  for(i=0;i<pp->nexact;i++){
    idx = pp->idx_exact[i];
    nbits = ceil(log2(ist->normsq[idx]+1));
    width_exact = ist->normsq[idx] / (iwt->n[idx] * N);
    width_powers = (ONE << (2*nbits+2))/N;

    polxvec_init_subvec2(exact[i], sx, pp->off_exact[i], 1, iwt->n[idx]);
    polxvec_init_subvec2(liftdec[i], sx, nn + i*pp->digits_liftings, 1, 
                         pp->digits_liftings);
    polxvec_init_subvec2(diff[i], sx, nn+pp->nexact*pp->digits_liftings+i, 1, 1);
    polxvec_init_subvec2(sigma[i], sigma1d, off_exact, 1, iwt->n[idx]);
    polxvec_init_subvec2(lift[i], lift1d, i, 1, 1);
    if(idx_merge < pp->nexact_merge && pp->exact_map[idx_merge] == i){
      polxvec_init_subvec2(exact_merge[idx_merge], sx, pp->off_exact[i], 1, 
                           pp->len_exact_merge[idx_merge]);
      idx_merge++;
    }

    if(pp->nquad == 0){
      polxvec_frompolyvec(exact[i], iwt->s[idx], 1, iwt->n[idx], width_exact);
    }

    polxvec_sigmam1(sigma[i], exact[i]);

    normsq = polyvec_sprodz(iwt->s[idx], iwt->s[idx], 1, 1, iwt->n[idx]);
    poly_binary_fromuint64(sout[pp->off_diff+i], ist->normsq[idx] - normsq);
    polxvec_frompolyvec(diff[i], &sout[pp->off_diff + i], 1, 1, N);

    polxvec_sprod(lift[i], exact[i], sigma[i]);
    sigmapower2(powers64, nbits);
    polxvec_fromint64vec2(powers, powers64, 1, 1, width_powers);
    polxvec_sprod_add(lift[i], diff[i], powers);
    polzvec_frompolxvec(&liftz, lift[i], 0, 1, 1);
    polz_setcoeff_fromint64(liftz, 0, 0);
    polz_center(liftz);
    polz_decompose(&sout[pp->off_liftings + pp->digits_liftings*i], liftz, 1,
                   pp->digits_liftings, pp->base_liftings);
    polxvec_frompolyvec(liftdec[i], &sout[pp->off_liftings+i*pp->digits_liftings],
                        1, pp->digits_liftings, WIDTHMOD(pp->base_liftings));

    off_exact += iwt->n[idx];
  }

  if(pp->randlen > 0){
    randombits64(bufbits, pp->randlen * N);
    polyvec_fromint64vec(&sout[pp->off_rand], bufbits, 1, pp->randlen, 1, NULL);
  }

  kappa_max = 0;
  for(i=0;i<pp->nincom;i++){
    kappa_max = MAX(kappa_max, pp->kappa_inner[i]);
  }
  kappa_max = MAX(kappa_max, pp->kappa_middle);
  kappa_max = MAX(kappa_max, pp->kappa_outer);

  polxvec_init(tx, kappa_max, 1);
  for(i=0;i<pp->nincom;i++){
    polxvec_init_subvec(tx, tx, 0, 1, pp->kappa_inner[i]);
    polxvec_init_subvec(sx, sx, pp->incom_offw[i], 1, pp->incom_lenw[i]);
    commit(tx, sx);
    polxvec_decompose(&sout[pp->off_incom[i]], tx, tx->len, pp->digits_unif,
                      pp->base_unif);
  }
  polxvec_init_subvec(sx, sx, 0, 1, 0);

  polxvec_init(incom, pp->len_com_inner, 1);
  polxvec_init_subvec(tx, tx, 0, 1, pp->kappa_middle);
  polxvec_frompolyvec(incom, &sout[pp->off_incom[0]], 1, pp->len_com_inner,
                      WIDTHMOD(pp->base_unif));
  commit(tx, incom);
  polxvec_bindec(&sout[pp->off_midcom], tx, tx->len, LOGQ);

  polxvec_init(midcom, pp->kappa_middle * LOGQ + pp->randlen, 1);
  polxvec_init_subvec(tx, tx, 0, 1, pp->kappa_outer);
  polxvec_frompolyvec(midcom, &sout[pp->off_midcom], 1, 
                      pp->kappa_middle * LOGQ, 0.5);
  if(pp->randlen > 0){
    polxvec_init_subvec(midcom, midcom, pp->kappa_middle * LOGQ, 1, pp->randlen);
    polxvec_frompolyvec(midcom, &sout[pp->off_rand], 1, pp->randlen, 0.5);
    polxvec_init_subvec(midcom, midcom, 0, 1, 0);
  }
  commit(tx, midcom);
  polzvec_frompolxvec(pi->com, tx, 0, 1, pp->kappa_outer);
  update_hash_polz(ost->h, pi->com, pp->kappa_outer);

  if(pp->nexact > 0){
    polxvec_init(chalx_exact, pp->nexact, 1);
    sample_chalx_aggregate(chalx_exact, ost->h);
    for(i=0;i<pp->nexact;i++){
      polxvec_init_subvec(chalx_exact, chalx_exact, i, 1, 1);
      polxvec_mul(sigma[i], chalx_exact, sigma[i]);
      polxvec_decompose(&sout[pp->off_sigma[i]], sigma[i], sigma[i]->len, 1, 15);
    }
    polxvec_init_subvec(chalx_exact, chalx_exact, 0, 1, 0);
  }

  if(pp->nquad > 0){
    polxvec_init(quad_agg, pp->quad_maxrank, 1);
    polxvec_init(chalx_times_coeff, pp->quad_maxrank, 1);
    polxvec_init(chalx_quad, pp->quad_sumranks, 1);
    sample_chalx_aggregate(chalx_quad, ost->h);

    off = 0;
    off_chal = 0;
    for(i=0;i<ist->rqcnst->nsparse;i++){
      len = ist->rqcnst->sparse[i]->quad->len;
      if(len == 0) continue;

      rank = ist->rqcnst->sparse[i]->b->len;
      polxvec_init_subvec(chalx_quad, chalx_quad, off_chal, 1, rank);
      polxvec_init_subvec(chalx_times_coeff, chalx_times_coeff, 0, 1, rank);
      for(j=0;j<len;j++){
        quad1 = ist->rqcnst->sparse[i]->quad->rows[j];
        quad2 = ist->rqcnst->sparse[i]->quad->cols[j];

        polyvec_copy(&sout[pp->off_quad_right+off], iwt->s[quad2], 1, 1, 
                     iwt->n[quad2]);

        polxvec_polx_mul(chalx_times_coeff, ist->rqcnst->sparse[i]->quad->coeffs[j],
                         chalx_quad);
        polxvec_init_subvec(quad_agg, quad_agg, 0, 1, rank);
        
        for(k=0;k<iwt->n[quad1];k+=rank){
          polxvec_init_subvec(quad_left, sx, off_map[quad1] + k, 1, rank);
          polxvec_setzero(quad_agg, 0, 1, rank);
          polxvec_rotation_aggregate_add(quad_agg, chalx_times_coeff, quad_left);

          polxvec_decompose(&sout[pp->off_quad_left+off], quad_agg, 
                            pp->len_quad, pp->digits_quad_left,
                            pp->base_quad_left);
          off += rank;
        }
      }
      off_chal += rank;
    }
    polxvec_free(quad_agg);
    polxvec_free(chalx_times_coeff);
  }
  polxvec_init_subvec(chalx_quad, chalx_quad, 0, 1, 0);

  dch_addchecks(ost, pp, ist, pi, chalx_exact, chalx_quad, off_map, nn);

  // free

  if(pp->nexact > 0){
    polxvec_free(lift1d);
    polxvec_free(powers);
    polxvec_free(sigma1d);
    polxvec_free(chalx_exact);
  }
  if(pp->nquad > 0){
    polxvec_free(chalx_quad);
  }
  
  polxvec_free(sx);
  polxvec_free(tx);
  polxvec_free(incom);
  polxvec_free(midcom);
  free(off_map);
  free(exact);
}

static void dch_reduce_impl(
  statement ost,
  const statement ist,
  const dch_proof pi,
  const dch_params pp, int borrow_public
)
{
  size_t i, *off_map, nn;
  polxvec chalx_exact, chalx_quad;

  dch_comkey_init(pp);
  dch_statement_init(ost, ist, pp, borrow_public);

  if(pp->nexact == 0 && pp->nquad == 0){
    return;
  }

  off_map = _malloc(ist->r * sizeof(size_t));
  nn = 0;
  for(i=0;i<ist->r;i++){
    off_map[i] = nn;
    nn += ist->n[i];
  }

  update_hash_polz(ost->h, pi->com, pp->kappa_outer);

  if(pp->nexact > 0){
    polxvec_init(chalx_exact, pp->nexact, 1);
    sample_chalx_aggregate(chalx_exact, ost->h);
  }
  if(pp->nquad > 0){
    polxvec_init(chalx_quad, pp->quad_sumranks, 1);
    sample_chalx_aggregate(chalx_quad, ost->h);
  }

  dch_addchecks(ost, pp, ist, pi, chalx_exact, chalx_quad, off_map, nn);

  if(pp->nexact > 0){
    polxvec_free(chalx_exact);
  }
  if(pp->nquad > 0){
    polxvec_free(chalx_quad);
  }

  free(off_map);
}

void dch_pack_proof_free(dch_pack_proof pi){
  dch_proof_free(pi->pi_dch);
  pack_proof_free(pi->pi_pack);
}

int dch_pack_params_gen(
  dch_pack_params pp, 
  size_t *pibits, 
  const statement st, 
  int zk
)
{
  size_t i, pibits_tmp, owtbits;
  statement st_pack;

  if(dch_params_gen(pp->pp_dch, &pibits_tmp, &owtbits, st, zk)){
    return 1;
  }
  *pibits = pibits_tmp;

  statement_init(st_pack, pp->pp_dch->r, pp->pp_dch->r + pp->pp_dch->nbin_merge);
  for(i=0;i<st_pack->r;i++){
    st_pack->n[i] = pp->pp_dch->n[i];
    st_pack->normsq[i] = pp->pp_dch->normsq[i];
    st_pack->normty[i] = pp->pp_dch->normty[i];
  }
  for(i=0;i<pp->pp_dch->r;i++){
    if(st_pack->normty[i] == BIN){
      st_pack->n[st_pack->r] = st_pack->n[i];
      st_pack->normsq[st_pack->r] = st_pack->normsq[i];
      st_pack->normty[st_pack->r] = BIN;
      st_pack->r++;
    }
  }
  if(pp->pp_dch->nexact + pp->pp_dch->nbin_merge > 0){
    st_pack->zqcnst->nsigmam1 = 1;
  }

  pack_params_gen(pp->pp_pack, &pibits_tmp, st_pack, zk, owtbits);
  *pibits += pibits_tmp;

  st_pack->zqcnst->nsigmam1 = 0;
  statement_free(st_pack);
  return 0;
}

void dch_pack_params_print(const dch_pack_params pp){
  dch_params_print(pp->pp_dch);
  pack_params_print(pp->pp_pack);
  printf("\n");
}

void dch_pack_params_free(dch_pack_params pp){
  dch_params_free(pp->pp_dch);
  pack_params_free(pp->pp_pack);
}

/* Standalone outputs may outlive their input; keep their deep-copy contract. */
void dch_prove(dch_proof pi, statement ost, witness owt,
               const statement ist, const witness iwt, const dch_params pp) {
  dch_prove_impl(pi, ost, owt, ist, iwt, pp, 0);
}
void dch_reduce(statement ost, const statement ist,
                const dch_proof pi, const dch_params pp) {
  dch_reduce_impl(ost, ist, pi, pp, 0);
}

int dch_pack_prove(
  dch_pack_proof pi, 
  const statement ist, 
  const witness iwt, 
  const dch_pack_params pp
)
{
  statement st_pack;
  witness wt_pack;
  timing time;

  timing_start(&time, "Dachshund Prover");

  quil_resource_trace("dachshund_prove_begin");
  /* ist outlives st_pack; Pack only reads these original coefficients. */
  dch_prove_impl(pi->pi_dch, st_pack, wt_pack, ist, iwt, pp->pp_dch, 1);
  quil_resource_trace("dachshund_prove_end");

  compile_bincnst(st_pack, wt_pack);
  quil_resource_trace("binary_constraints_ready");

  timing_end(&time);
  timing_print(&time, 1);

  timing_start(&time, "Pack Prover");

  quil_resource_trace("pack_prove_begin");
  int status=pack_prove(pi->pi_pack, st_pack, wt_pack, pp->pp_pack);
  quil_resource_trace("pack_prove_end");

  timing_end(&time);
  timing_print(&time, 1);

  statement_free(st_pack);
  witness_free(wt_pack);
  return status;
}

int dch_pack_verify(
  const statement ist, 
  const dch_pack_params pp, 
  const dch_pack_proof pi
)
{
  int ret;
  statement st_pack;
  timing time;

  timing_start(&time, "Dachshund Verifier");

  /* Free st_pack below before returning to the owner of ist. */
  dch_reduce_impl(st_pack, ist, pi->pi_dch, pp->pp_dch, 1);

  compile_bincnst(st_pack, NULL);

  timing_end(&time);
  timing_print(&time, 1);

  timing_start(&time, "Pack Verifier");

  ret = pack_verify(st_pack, pp->pp_pack, pi->pi_pack);

  timing_end(&time);
  timing_print(&time, 1);

  statement_free(st_pack);
  return ret;
}
