#include "probe_mask_width.h"
#include "aesctr.h"
#include "comkey.h"
#include "data.h"
#include "fips202.h"
#include "jlproj.h"
#include "malloc.h"
#include "lnp.h"
#include "poly.h"
#include "polz.h"
#include "randombytes.h"
#include "rejection.h"
#include "private_sampling_params.h"
#include "private_mask_range.h"
#include "resource_trace.h"
#include "refresh_parallel.h"
#include "lnp_parallel.h"

#include <assert.h>
#include <math.h>
#include <string.h>

#if LOGQ >= 63 
#error "Q too large."
#else
#define Q (((__int128)1 << LOGQ) - QOFF)
#endif

// debug option
#ifndef JLMATZERO
#define JLMATZERO 0
#endif
#ifndef UIZERO
#define UIZERO 0
#endif
#ifndef UIMAX
#define UIMAX 0
#endif
#ifndef YZERO
#define YZERO 0
#endif
#ifndef NOMASK
#define NOMASK 0
#endif
#ifndef RANDZERO
#define RANDZERO 0
#endif
#ifndef NOREJ
#define NOREJ 0
#endif
//#define DEBUG 0

/* Token-proof builds must never enable internal witness/constraint dumps or
 * disable masking. Debug symbols and runtime assertions remain supported. */
#if defined(DEBUG) || NOMASK != 0 || NOREJ != 0 || RANDZERO != 0 \
    || JLMATZERO != 0 || UIZERO != 0 || UIMAX != 0 || YZERO != 0
#error "Native token proofs prohibit debug dumps and disabled randomness, masking or rejection"
#endif


#define GTAILBND QUIL_PRIVATE_REJECTION_TAIL // gaussian tail bound
// extra bits beyond logsdp for yhat decomposition:
// sdp = 1.55*2^logsdp, max coeff = GTAILBND*sdp = 14*1.55*2^logsdp
// ceil(log2(14*1.55)) + 1 (sign) = 5 + 1 = 6
#define YHAT_EXTRA_BITS 6

// len s2 in ajtaij commitment
#if N == 256
#define KAPPA_MLWE 6
#endif

static void print_sparsecnst (sparsecnst cnst);

static void print_sparsecnst (sparsecnst cnst) {
    size_t i, j, row, col, off, len;
    polxvec sv;
    int is_quad, nzeros;

    is_quad = cnst->b->len > 1 ? 0 : 1;

    printf ("%s cnst:\n", is_quad ? "quad" : "lin");

    if (is_quad) {
        printf (" quad:\n");
        for (i = 0; i < cnst->quad->len; i++) {
            row = cnst->quad->rows[i];
            col = cnst->quad->cols[i];
            printf (" a[%lu,%lu] * <wt[%lu],wt[%lu]>\n", row, col, row, col);
        }
    }
    
    for (i = 0; i < cnst->lin->nparts; i++) {
        off = cnst->lin->off[i];
        len = cnst->lin->phi[i]->len;

        nzeros = 0;
        for (j = 0; j < cnst->lin->phi[i]->len; j++) {
            polxvec_init_subvec2 (sv, cnst->lin->phi[i], j, 1, 1);
            if (polxvec_iszero (sv)) {
                nzeros++;
            }
        }
        printf (" <phi[%lu],wt(off:%lu,len:%lu,zeros:%d)>\n", i, off, len, nzeros);
    }

    if (polxvec_iszero (cnst->b) == 0)
        printf (" - b\n");
}

static void lnp_aggregate_rq(
  sparsecnst finalcnst,
  const lnp_params pp,
  const statement ist,
  const sparsecnst zqagg[LIFTS],
  uint8_t h[HASHLEN]
);
static void lnp_addcheck_finalcnst (sparsecnst cfinalcnst, polx cx, const sparsecnst finalcnst, const lnp_params pp);
static void polz_topoly_(poly r, const polz a);
static void polzvec_topolyvec_(poly *r, const polz *a, size_t len);
static int __reject_decomp_proj (poly *w, poly *t, polz *v0, const polz *maskedproj, size_t len, size_t k);
static void lnp_aggregate_zq(
  sparsecnst *zqagg,
  const lnp_params pp,
  const statement ist,
  const uint8_t *jlmat1,
  const uint8_t *jlmat2,
  const uint8_t *jlmat3,
  const uint8_t *jlmat4,
  const polz *zp,
  uint8_t h[HASHLEN]
);

static void polz_topoly_(poly r, const polz a) {
  int64_t coeffi64;
  zz coeffzz;
  size_t i;

  for(i = 0; i < N; i++) {
    polz_getcoeff(coeffzz, a, i);
    coeffi64 = int64_fromzz(coeffzz);
    assert (coeffi64 < (int64_t)1 << 13);
    assert (coeffi64 > -((int64_t)1 << 13));
    r->c[i] = coeffi64;
  }
}

static void polzvec_topolyvec_(poly *r, const polz *a, size_t len) {
  size_t i;

  for(i=0;i<len;i++)
    polz_topoly_(r[i],a[i]);
}

static void comcnst_eval_(polxvec ev, const comcnst cnst, const polxvec sx);
static void comcnst_eval_(polxvec ev, const comcnst cnst, const polxvec sx){
  size_t i, j, rank;
  polxvec tmp, comkey_sv, sx_sv, phi_sv;

  rank = cnst->rank;
  polxvec_setzero(ev, 0, 1, rank);
  polxvec_init(tmp, rank, 1);

  for(i=0;i<cnst->ncom;i++){
    polxvec_init_subvec(comkey_sv, comkey, cnst->comk_off[i], 1,
                        comkey->len - cnst->comk_off[i]);
    polxvec_init_subvec(sx_sv, sx, cnst->comw_off[i], 1, cnst->comw_len[i]);
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
      polxvec_init_subvec(sx_sv, sx, cnst->phiw_off[i] + j*rank, 1, rank);
      polxvec_init_subvec(phi_sv, cnst->phi[i], j, 1, 1);
      polxvec_mul_add(ev, phi_sv, sx_sv);
    }
  }

  polxvec_sub(ev, ev, cnst->b);

  polxvec_free(tmp);
}

static int _get_params_rejstd (long double *capm, unsigned int *log2sd, long double *sd,
                                long double *gamma, long double t);
static int _get_params_rejsgnleak (long double *capm, unsigned int *log2sd, long double *sd,
                                    long double *gamma, long double t);
static void lnp_sample_chalx_armortize(polx *c, uint8_t h[HASHLEN]);
static void lnp_addcheck_commmit (comcnst c[4], const lnp_params pp, const lnp_proof pi);
static void lnp_addcheck_commmit_in_clear (comcnst c, const polz *capu, size_t rank, 
                               size_t off, size_t len);
static void lnp_addcheck_lift_zero_coeff(sparsecnst c[LIFTS], size_t off);
static void lnp_addchecks(statement ost, const lnp_params pp, const lnp_proof pi, polx chalx, sparsecnst finalcnst);
// s-opening: stilde is scattered across Z1S10..Z1S50 / Z1LO with a split A1.
// z2s (= rs) lives inside the merged Z1LO/Z1HI block after s3+s6.
static void lnp_addcheck_sopening(comcnst cnst, const lnp_params pp, polx chalx);
// v-opening: z1v is contiguous at Z1V10..Z1V20, z2v (= rv) within Z1LO/Z1HI.
static void lnp_addcheck_vopening(comcnst cnst, const lnp_params pp, polx chalx);
static void __print_bytes(uint8_t *bytes, size_t len);
static uint64_t normsq_u (size_t dim, size_t log2b);
static uint64_t normsq_g (size_t dim, size_t log2b, long double sd);
static void ist_shift_positions(const statement ist, const lnp_params pp, int dir);

static void __print_bytes(uint8_t *bytes, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
        if (i < len - 1)
            printf(" ");
        if ((i + 1) % 8 == 0 || (size_t)i == len)
            printf("\n");
    }
}

static uint64_t normsq_u (size_t dim, size_t log2b) {
    return 1.3 * dim * (1ULL << (2 * log2b)) / 12;
}

static uint64_t normsq_g (size_t dim, size_t log2b, long double sd) {
    return 1.3 * dim * sd * sd / (1ULL << (2 * log2b));
}

// translate ist constraint positions between the input-witness layout
// (s1|s2|s3|s4|s5 concatenated) and the merged output layout
// where Z1LO = s3||s6||z2 introduces a "gap" after s3.
// dir = +1: forward (input layout -> merged)
// dir = -1: inverse (merged layout -> input)
// positions < silen[0]+silen[1]+silen[2] are unchanged
// other positions shift by delta = silen[5]+rslen+rvlen
static void ist_shift_positions(const statement ist, const lnp_params pp, int dir) {
    const size_t thresh_fwd = pp->silen[0] + pp->silen[1] + pp->silen[2];
    const size_t delta = pp->silen[5] + pp->rslen + pp->rvlen;
    const size_t thresh = (dir > 0) ? thresh_fwd : thresh_fwd + delta;
    size_t i, j;

#define SHIFT(p) do { if ((p) >= thresh) { if (dir > 0) (p) += delta; else (p) -= delta; } } while (0)
    for (i = 0; i < ist->rqcnst->nsparse; i++) {
        for (j = 0; j < ist->rqcnst->sparse[i]->lin->nparts; j++)
            SHIFT(ist->rqcnst->sparse[i]->lin->off[j]);
    }
    for (i = 0; i < ist->rqcnst->ncom; i++) {
        for (j = 0; j < ist->rqcnst->com[i]->ncom; j++)
            SHIFT(ist->rqcnst->com[i]->comw_off[j]);
        for (j = 0; j < ist->rqcnst->com[i]->nphi; j++)
            SHIFT(ist->rqcnst->com[i]->phiw_off[j]);
    }
    for (i = 0; i < ist->zqcnst->nsparse; i++) {
        for (j = 0; j < ist->zqcnst->sparse[i]->lin->nparts; j++)
            SHIFT(ist->zqcnst->sparse[i]->lin->off[j]);
    }
    for (i = 0; i < ist->zqcnst->nsigmam1; i++) {
        SHIFT(ist->zqcnst->sigmam1[i]->off1);
        SHIFT(ist->zqcnst->sigmam1[i]->off2);
    }
#undef SHIFT
}

int lnp_reduce (statement ost, const statement ist, const lnp_proof pi, const lnp_params pp) {
    sparsecnst zqagg[LIFTS];
    polx chalx;
    uint8_t *jlmat1, *jlmat2;
    uint8_t *jlmat3, *jlmat4;
    polxvec ppowers, m1powers, phi;
    long double l2z, l2z_ub;
    size_t i;
    int reject;
    sparsecnst finalcnst;

    reject = 1;
    jlmat1 = NULL;
    jlmat3 = NULL;

    // check norm on z = m[2]
    l2z = polzvec_norm (pi->m[2], 256 / N);
    l2z_ub = sqrtl(512) * pp->sdp;
    if (l2z > l2z_ub) {
        // fprintf (stderr,"ERROR in lnp_reduce: norm of z is larger than the bound (%0.2Lf > %0.2Lf)\n", l2z, l2z_ub);
        goto ret;
    }

    lnp_statement_init (ost, ist, pp);
    lnp_comkey_init (pp);

    // hash U1
    update_hash_polz(ost->h, pi->m[0], pp->kappa_linfmsis);
    //__print_bytes(ost->h, 16);

    // aggregate projections 1

    quil_resource_trace("lnp_jl_sample_begin");
    jl_sample_mat (&jlmat1, &jlmat2, ost->h, pp->silen_max); // changes hash

    // hash U2
    update_hash_polz(ost->h, pi->m[1], pp->kappa_linfmsis);
    //__print_bytes(ost->h, 16);

    jl_sample_mat (&jlmat3, &jlmat4, ost->h, pp->vtildelen / 2);
#if JLMATZERO == 1
    memset (jlmat3, 0,  (pp->vtildelen / 2) * 256 * N / 8);
    memset (jlmat3 + (pp->vtildelen / 2) * 256 * N / 8, 0xff,  (pp->vtildelen / 2) * 256 * N / 8);
#endif

    quil_resource_trace("lnp_jl_sample_end");
    // hash z
    update_hash_polz(ost->h, pi->m[2], 256 / N);
    //__print_bytes(ost->h, 16);

    // shift ist's constraint positions into merged layout for aggregation.
    ist_shift_positions(ist, pp, +1);

    quil_resource_trace("lnp_aggregate_zq_begin");
    lnp_aggregate_zq (zqagg, pp, ist, jlmat1, jlmat2, jlmat3, jlmat4, pi->m[2], ost->h);
    quil_resource_trace("lnp_aggregate_zq_end");
    // Match the prover's normalization before forming lifted ring equations.
    quil_resource_trace("lnp_zq_refresh_begin");
    for(i=0;i<LIFTS;i++) quil_sparsecnst_parallel_refresh(zqagg[i]);
    quil_resource_trace("lnp_zq_refresh_end");

    // create vanishing constraints

    polxvec_init (ppowers, LOGQ, 1);
    polxvec_init (m1powers, LOGQ, 1);
    polxvec_powers (ppowers, 2, 1, -1); // G2
    polxvec_powers (m1powers, 2, -1, 1); // -G2

    for (i = 0; i < LIFTS; i++) {
        // +G2*gihat
        polxvec_init_subvec2 (phi, zqagg[i]->lin->phi[0], pp->off[Z1LO] + pp->silen[2] + i*LOGQ, 1, LOGQ);
        polxvec_copy (phi, ppowers);
        // -G2*hihat
        polxvec_init_subvec2 (phi, zqagg[i]->lin->phi[0], pp->off[HHAT] + i*LOGQ, 1, LOGQ);
        polxvec_copy (phi, m1powers);
    }

    // hash U4
    update_hash_polz(ost->h, pi->m[3], pp->kappa_linfmsis);
    //__print_bytes(ost->h, 16);

    quil_resource_trace("lnp_aggregate_rq_begin");
    lnp_aggregate_rq (finalcnst, pp, ist, zqagg, ost->h);
    quil_resource_trace("lnp_aggregate_rq_end");
    // Aggregation owns its result; the source constraints are no longer needed.
    for (i = 0; i < LIFTS; i++) sparsecnst_free(zqagg[i]);

    ist_shift_positions(ist, pp, -1);

    // hash U5
    update_hash_polz(ost->h, pi->m[4], pp->kappa_linfmsis);
    //__print_bytes(ost->h, 16);

    sample_chalx_amortize (&chalx, 1, ost->h);

    quil_resource_trace("lnp_checks_begin");
    lnp_addchecks (ost, pp, pi, chalx, finalcnst);
    quil_resource_trace("lnp_checks_end");
    sparsecnst_free(finalcnst);
    polxvec_free(ppowers);
    polxvec_free(m1powers);

    reject = 0;
ret:
    free (jlmat1);
    free (jlmat3);
    return reject;
}

int lnp_prove(lnp_proof pi, statement ost, witness owt, const statement ist, const witness iwt, const lnp_params pp) {
    //__attribute__((aligned(64))) uint8_t hashbuf[64 + QBYTES * 256 + 24];
    polz v0[LNP_NPROJ * 256 / N];
    poly vtilde[LNP_NPROJ * 256 / N * 2 * 2]; // (w,t,sigmam1(w),sigmam1(t))
    int64_t ub;
    sparsecnst zqagg[LIFTS];
    polz y[256 / N];
    polz zp[256 / N];
    polz pv[256 / N];
    polz g[LIFTS];
    polz umask[LNP_NPROJ][256 / N];
    poly r[KAPPA_MLWE];
    poly ghat[LOGQ * LIFTS];
    poly yhat[LOGQ * 256 / N];
    poly umaskhat[LOGQ * 256 / N * LNP_NPROJ];
    polx cx;
    uint64_t nonce;
    uint64_t coeffs[KAPPA_MLWE];
    uint8_t seed[32];
    uint8_t *jlmat1=NULL, *jlmat2;
    uint8_t *jlmat3=NULL, *jlmat4;
    size_t i, j, off, len;
    int64_t proji64[256];
    int32_t proji32[256];
    int64_t sprod_zv, sprod_vv;
    aes256ctr_ctx state;
    quil_prg_stream private_stream={&state,quil_prg_aes256_squeeze};
    uint8_t tmp_h[HASHLEN];
    // beta[i] <= 13, 2^k[i] ~ 9.75*13 ~ 17 bits
    // => sample 3 uniform bytes per coeff
    const size_t nblocks = (3 * N * LNP_NPROJ + 1) / AES256CTR_BLOCKBYTES;
    uint8_t umaskbytes[nblocks * AES256CTR_BLOCKBYTES];
    int64_t umaski64[N];
    poly *sout;
    int reject;
    int status = 0;
    polxvec svcom;
    polxvec tmp1x, tmp2x, iwtx;
    polxvec sv1, sv2;
    polxvec stildex, vtildex, rsx, rvx;
    polxvec svtildex, rsvx;
    polxvec tsx, tshatx, capu1;
    polxvec tvx, tvv0hatx, capu2;
    polxvec hhatx, capu4;
    polz projz[256 / N];
    size_t maxtmplen, v0off, umhat_off, umaskhatlen, yhatlen, tvv0len;

    polxvec wsx, y1sx, y2sx, wvx, y1vx, y2vx, u5vecx, capu5, y2sx_bak;
    polxvec z1x, z2x, csvtildex, crsvx, capa2s, capa2v;
    polxvec src_sv, dst_sv; // scatter/gather views for merged-layout copies
    polxvec ck_sv, s_sv;    // views for the split A1 commitment calls
    polxvec wsy1, wvy1;
    polxvec g0, g1, u, v, sp, yxq[7];
    polx *aij;
    size_t row, col;
    size_t s123_len, s45_len; // common sub-block lengths
    size_t ck_off; // running comkey offset within the split A1
    size_t stride, z1lo_out, z1_pos; // z1 decomposition helpers
    polz *csvtilde;
    polz *crsv;
    uint64_t mask;

    csvtilde = _aligned_alloc (64, (pp->stildelen + pp->vtildelen) * sizeof(polz));
    crsv = _aligned_alloc (64, (pp->rslen + pp->rvlen) * sizeof(polz));

    polz *z1;
    polz *z2;
    z1 = _aligned_alloc (64, (pp->stildelen + pp->vtildelen) * sizeof(polz));
    z2 = _aligned_alloc (64, (pp->rslen + pp->rvlen) * sizeof(polz));
    polz *z1s = &z1[0]; 
    polz *z1v = &z1[pp->stildelen]; 
    polz *z2s = &z2[0]; 
    polz *z2v = &z2[pp->rslen];

    // witness must be of the form z0, z1, that||ghat||hhat
    assert(iwt->r == 5);
    assert(ist->r == 5);
    assert(ist->normty[0] == L2APPROX);
    assert(ist->normty[1] == L2APPROX);
    assert(ist->normty[2] == L2APPROX);
    assert(ist->normty[3] == BIN);
    assert(ist->normty[4] == L2APPROX);
    assert(verify(ist, iwt));

    lnp_witness_init(owt, pp);
    lnp_statement_init(ost, ist, pp);
    lnp_proof_init(pi, pp);
    lnp_comkey_init(pp);
    sout = owt->s[0];

    maxtmplen = pp->stildelen + MAX(pp->rslen, pp->vtildelen);
    polxvec_init (tmp1x, maxtmplen, 1);
    polxvec_init (tmp2x, maxtmplen, 1);

    polxvec_init (svtildex, pp->stildelen + pp->vtildelen, 1);
    polxvec_init (rsvx, pp->rslen + pp->rvlen, 1);

    // comkey parts
    polxvec_init_subvec2 (capa2s, comkey, pp->a2soff, 1, comkey->len - pp->a2soff);
    polxvec_init_subvec2 (capa2v, comkey, pp->a2voff, 1, comkey->len - pp->a2voff);

    // convert input witness s1..s5 to polx
    polxvec_init (iwtx, pp->slen, 1);
    off = 0;
    for (i = 0; i < 5; i++) {
      polxvec_init_subvec (stildex, iwtx, off, 1, iwt->n[i]);
      polxvec_frompolyvec (stildex, iwt->s[i], 1, iwt->n[i], 1);
      off += iwt->n[i];
    }

    // internal randomness 1
    randombytes (seed, sizeof(seed));
    nonce = 0;

    aes256ctr_init(&state, seed, nonce);
    nonce++;

rej_loop1:
    // save hash before rejection sampling
    memcpy (tmp_h, ost->h, HASHLEN);

    // y: gaussian masks
    if(quil_polzvec_gaussian_private(y, 256 / N, pp->logsdp, seed, nonce++)) { status=1;goto cleanup_early; }
#if YZERO == 1
    int64_t xxcoefs[256] = {0};
    xxcoefs[0] = -1;
    polzvec_fromint64vec (y, 1, 1, xxcoefs);
#endif
    // printf("y\n");
    // polz_printint64(y);
    if(!quil_private_mask_fits(y,256/N,pp->logsdp+YHAT_EXTRA_BITS)
       || !(polzvec_norm(y,256/N) < GTAILBND*sqrtl(256)*pp->sdp)) {
      status=1;goto cleanup_early;
    }
    polzvec_bindec (yhat, y, 256 / N, 256 / N, pp->logsdp + YHAT_EXTRA_BITS);
    assert (polyvec_isbinary (yhat, 1, (pp->logsdp + YHAT_EXTRA_BITS) * 256 / N));

    // g: uniform masks with ct = 0
    quil_polzvec_uniform_private(g, LIFTS, seed, nonce++);
    for (i = 0; i < LIFTS; i++) {
        for (j = 0; j < L; j++)
            g[i]->limbs[j]->c[0] = 0;
        polz_reduce(g[i]);
        polz_center(g[i]);
        // printf("g[%lu]\n", i);
        // polz_printint64(g[i]);
        polzvec_bindec (&ghat[i*LOGQ], &g[i], 1, 1, LOGQ); // g already centered
    }

    assert (polyvec_isbinary (ghat, 1, LOGQ * LIFTS));

    // umask[i]: mask uniform mod 2^k[i]
    umhat_off = 0;
    for (i = 0; i < LNP_NPROJ; i++) {
        aes256ctr_squeezeblocks (umaskbytes, nblocks, &state);
        for (j = 0; j < N; j++) {
            umaski64[j] = (umaskbytes[3 * j + 0]
                           + (umaskbytes[3 * j + 1] << 8)
                           + (umaskbytes[3 * j + 2] << 16));
            mask = ~((~(uint64_t)0) << pp->k[i]);
            umaski64[j] &= mask; // truncate 2^24 -> 2^k[i]
            // center mod 2^k
            ub = ((uint64_t)1 << (pp->k[i] - 1)) - 1;
            if (umaski64[j] > ub)
                umaski64[j] -= ((uint64_t)1 << pp->k[i]);
        }
        polzvec_fromint64vec(umask[i], 256 / N, 1, umaski64);
        // polz_printint64(umask[i]);
        polzvec_bindec (&umaskhat[umhat_off], umask[i], 256 / N, 256 / N, pp->k[i]);
#if UIZERO == 1
        polzvec_setzero (&umask[i][0], 256 / N);
        polyvec_setzero (&umaskhat[umhat_off], 1, pp->k[i] * 256 / N);
#elif UIMAX == 1
        for (j = 0; j < N; j++)
           umaski64[j] = 1;
        umaski64[0] = ub;
        polzvec_fromint64vec(umask[i], 256 / N, 1, umaski64);
        polzvec_bindec (&umaskhat[umhat_off], umask[i], 256 / N, 256 / N, pp->k[i]);
#endif
        umhat_off += pp->k[i] * 256 / N;
    }

    // rs: binary mlwe secret, internal randomness 2
    randombytes ((uint8_t *)coeffs, sizeof(coeffs[0]) * pp->rslen);
    for (i = 0; i < pp->rslen; i++) {
        poly_binary_fromuint64(r[i], coeffs[i]);
        //printf("r[%lu]\n", i);
        //poly_print(r[i]);
#if RANDZERO == 1
        poly_setzero (r[i]);
#endif
    }
    assert (polyvec_isbinary(r, 1, pp->rslen));

    // commit ts = A1s*stilde + A2s*rs

    // copy pre-converted s1..s5 into stildex
    polxvec_init_subvec (stildex, tmp1x, 0, 1, pp->slen);
    polxvec_copy (stildex, iwtx);
    off = pp->slen;

    polxvec_init_subvec (stildex, tmp1x, off, 1, LIFTS * LOGQ);
    polxvec_frompolyvec (stildex, ghat, 1, LIFTS * LOGQ, 1);
    off += LIFTS * LOGQ;
    yhatlen = (pp->logsdp + YHAT_EXTRA_BITS) * 256 / N;
    polxvec_init_subvec (stildex, tmp1x, off, 1, yhatlen);
    polxvec_frompolyvec (stildex, yhat, 1, yhatlen, 1);
    off += yhatlen;
    umaskhatlen = pp->silen[5] - LOGQ * LIFTS - (pp->logsdp + YHAT_EXTRA_BITS) * 256 / N;
    polxvec_init_subvec (stildex, tmp1x, off, 1, umaskhatlen);
    polxvec_frompolyvec (stildex, umaskhat, 1, umaskhatlen, 1);
    off += umaskhatlen;
    assert (off == pp->stildelen);

    polxvec_init_subvec (rsx, tmp1x, off, 1, pp->rslen);
    polxvec_frompolyvec (rsx, r, 1, pp->rslen, 1);
    off += pp->rslen;
    assert (off == pp->stildelen + pp->rslen);

    polxvec_init_subvec (tsx, tmp2x, 0, 1, pp->kappa_l2msis1);
    polxvec_init_subvec (stildex, tmp1x, 0, 1, pp->stildelen);
    // split s-commitment at extension-ring boundaries for merged output
    s123_len = pp->silen[0] + pp->silen[1] + pp->silen[2];
    s45_len = pp->silen[3] + pp->silen[4];
    ck_off = 0;
    // A1_s123 * (s1||s2||s3)
    polxvec_init_subvec2(s_sv, stildex, 0, 1, s123_len);
    off = polxvec_sprod_extension(tsx, comkey, s_sv);
    ck_off += off;
    // A1_s45 * (s4||s5)
    polxvec_init_subvec2(ck_sv, comkey, ck_off, 1, comkey->len - ck_off);
    polxvec_init_subvec2(s_sv, stildex, s123_len, 1, s45_len);
    off = polxvec_sprod_extension_add(tsx, ck_sv, s_sv);
    ck_off += off;
    // A1_s6 * s6
    polxvec_init_subvec2(ck_sv, comkey, ck_off, 1, comkey->len - ck_off);
    polxvec_init_subvec2(s_sv, stildex, s123_len + s45_len, 1, pp->silen[5]);
    off = polxvec_sprod_extension_add(tsx, ck_sv, s_sv);
    ck_off += off;
    assert(ck_off == pp->a2soff);
    polxvec_sprod_extension_add (tsx, capa2s, rsx);
    polxvec_bindec (&sout[pp->off[TSHAT]], tsx, pp->kappa_l2msis1, LOGQ);

    // populate s-parts of (stilde,vtilde) and (rs,rv)
    polxvec_copy (svtildex, stildex);
    polxvec_copy (rsvx, rsx);

    // commit U1 = A*tshat

    polxvec_init_subvec (tshatx, tmp1x, 0, 1, pp->len[TSHAT]);
    polxvec_frompolyvec (tshatx, &sout[pp->off[TSHAT]], 1, pp->len[TSHAT], 1);

    polxvec_init_subvec (capu1, tmp2x, 0, 1, pp->kappa_linfmsis);
    commit (capu1, tshatx);
    polzvec_frompolxvec(pi->m[0], capu1, 0, 1, pp->kappa_linfmsis);
    update_hash_polz(tmp_h, pi->m[0], pp->kappa_linfmsis);
    //__print_bytes(tmp_h, 16);

    // 1.projection Pi*s[i] + umask[i] = 2^k[i]*v1[i] + v0[i]
    // v1 ternary, v0[i] uniform mod 2^k[i]
    // v1 = w - t, w,t binary

    jl_sample_mat (&jlmat1, &jlmat2, tmp_h, pp->silen_max);
#if JLMATZERO == 1
    memset(jlmat1, 0x00, pp->silen_max * 256 * N / 8);
    memset(jlmat1 + pp->silen_max * 256 * N / 8, 0xff, pp->silen_max * 256 * N / 8);
#endif

    off = 0;
    for (i = 0; i < LNP_NPROJ; i++) {
        jl_project (proji32, iwt->s[i], pp->silen[i], jlmat1, jlmat2);
        for(j = 0; j < 256; j++)
            proji64[j] = proji32[j];
        polzvec_fromint64vec (projz, 256 / N, 1,  proji64);
        polzvec_center (projz, 256 / N);
        polzvec_add (projz, projz, umask[i], 256 / N);
        polzvec_center (projz, 256 / N);

        reject = __reject_decomp_proj (vtilde + i * 256 / N, vtilde + LNP_NPROJ * 256 / N + i * 256 / N, v0 + i * 256 / N, projz, 256 / N, pp->k[i]);
#if !NOREJ
        if (reject) {// accept with prob. > 0.9999
            // printf("rejected v1[%lu]: too many carries\n", i);
            goto rej_loop1;
        }
#endif
    }
    assert (polyvec_isbinary(vtilde, 1, 2 * LNP_NPROJ * 256 / N));

    v0off = 0;
    for (i = 0; i < LNP_NPROJ; i++) {
        polzvec_bindec (sout + pp->off[V0HAT] + v0off, v0 + i, 256 / N, 256 / N, pp->k[i]);
        v0off += pp->v0ihatlen[i];
    }
    assert (v0off == pp->v0hatlen);

    // vtilde = (w,t,simgmam1(w),sigmam1(t))
    polyvec_sigmam1 (vtilde + 2 * LNP_NPROJ * 256 / N, vtilde, 1, 1, 2 * LNP_NPROJ * 256 / N);

    // rv: binary mlwe secret, internal randomness 3
    
    randombytes ((uint8_t *)coeffs, sizeof(coeffs[0]) * pp->rvlen);
    for (i = 0; i < pp->rvlen; i++) {
        poly_binary_fromuint64(r[i], coeffs[i]);
        //printf("r[%lu]\n", i);
        //poly_print(r[i]);
#if RANDZERO == 1
        poly_setzero (r[i]);
#endif
    }
    assert (polyvec_isbinary (r, 1, pp->rvlen));

    // commit tv = A1v*vtilde + A2v*rv

    off = 0;
    polxvec_init_subvec (vtildex, tmp1x, off, 1, pp->vtildelen);
    polxvec_frompolyvec (vtildex, vtilde, 1, pp->vtildelen, 1);
    off += pp->vtildelen;
    assert (off == pp->vtildelen);

    polxvec_init_subvec (rvx, tmp1x, off, 1, pp->rvlen);
    polxvec_frompolyvec (rvx, r, 1, pp->rvlen, 1);
    off += pp->rvlen;
    assert (off == pp->vtildelen + pp->rvlen);

    polxvec_init_subvec (tvx, tmp2x, 0, 1, pp->kappa_l2msis2);

    off = polxvec_sprod_extension (tvx, comkey, vtildex);
    assert (off == pp->a2voff);
    polxvec_sprod_extension_add (tvx, capa2v, rvx);
    polxvec_bindec (&sout[pp->off[TVHAT]], tvx, pp->kappa_l2msis2, LOGQ);

    // populate v-parts of (stilde,vtilde) and (rs,rv)
    polxvec_init_subvec (sv1, svtildex, pp->stildelen, 1, pp->vtildelen);
    polxvec_init_subvec (sv2, rsvx, pp->rslen, 1, pp->rvlen);
    polxvec_copy (sv1, vtildex);
    polxvec_copy (sv2, rvx);

    // commit U2 = A*(tvhat,v0hat)

    polxvec_init_subvec (capu2, tmp2x, 0, 1, pp->kappa_linfmsis);

    tvv0len = pp->len[TVHAT] + pp->len[V0HAT];
    polxvec_init_subvec (tvv0hatx, tmp1x, 0, 1, tvv0len);
    polxvec_frompolyvec (tvv0hatx, &sout[pp->off[TVHAT]], 1, tvv0len, 1);

    commit (capu2, tvv0hatx);
    polzvec_frompolxvec(pi->m[1], capu2, 0, 1, pp->kappa_linfmsis);
    update_hash_polz(tmp_h, pi->m[1], pp->kappa_linfmsis);

    // project v and mask the projection

    jl_sample_mat (&jlmat3, &jlmat4, tmp_h, pp->vtildelen / 2);
#if JLMATZERO == 1
    memset (jlmat3, 0,  (pp->vtildelen / 2) * 256 * N / 8);
    memset (jlmat3 + (pp->vtildelen / 2) * 256 * N / 8, 0xff,  (pp->vtildelen / 2) * 256 * N / 8);
#endif

    jl_project(proji32, vtilde, pp->vtildelen / 2, jlmat3, jlmat4);
    for(j = 0; j < 256; j++)
        proji64[j] = proji32[j];
    polzvec_fromint64vec(pv, 256 / N, 1,  proji64);

    polzvec_add (zp, y, pv, 256 / N);

    sprod_zv = polzvec_sprodz (zp, pv, 256 / N);
    sprod_vv = polzvec_sprodz (pv, pv, 256 / N);
    reject = quil_rejection_decide_sd_256_stream(&private_stream,0, sprod_zv, sprod_vv, pp->sdp, pp->capmp);
    if (reject < 0) { status = 1; goto cleanup_early; }
#if !NOREJ
    if (reject) {
        // printf("z rejected: <v,v>=%ld <z,pv>=%ld\n", sprod_vv, sprod_zv);
        free (jlmat1);jlmat1=NULL;
        free (jlmat3);jlmat3=NULL;
        goto rej_loop1;
    }
#endif
    memcpy (ost->h, tmp_h, HASHLEN); // store hash of accepted challange

    // sent z

    polzvec_copy (pi->m[2], zp, 256 / N);
    update_hash_polz(ost->h, pi->m[2], 256 / N);
    //__print_bytes(ost->h, 16);

    // shift ist's constraint positions into merged layout for aggregation.
    ist_shift_positions(ist, pp, +1);

    lnp_aggregate_zq (zqagg, pp, ist, jlmat1, jlmat2, jlmat3, jlmat4, zp, ost->h);
    for (i = 0; i < LIFTS; i++)
        sparsecnst_refresh(zqagg[i]);

    polxvec hix, sxl, sxq[NWIT], gx, phi, ppowers, m1powers, sv, yxl;
    polxvec __t;
    // yxl spans the uniform block of the merged layout (includes z2 gap inside Z1LO).
    polxvec_init (yxl, pp->off[Z1S11], 1);
    // The merged mask layout also reserves a zero z2 gap.
    polxvec_setzero(yxl, 0, 1, pp->off[Z1S11]);
    polxvec_init (y2sx_bak, pp->rslen, 1);
    polxvec_init (sxl, pp->wtlen, 1);
    // Reserved Gaussian slots are zero before the response step.
    polxvec_setzero(sxl, 0, 1, pp->wtlen);
    polxvec_init (hix, 1, 1);
    polxvec_init (gx, 1, 1);

    // scatter svtildex (natural s1|s2|s3|s4|s5|s6|v10|v20) into sxl (merged layout)
    s123_len = pp->silen[0] + pp->silen[1] + pp->silen[2];
    s45_len = pp->silen[3] + pp->silen[4];
    polxvec_init_subvec2(src_sv, svtildex, 0, 1, s123_len);
    polxvec_init_subvec2(dst_sv, sxl, pp->off[Z1S10], 1, s123_len);
    polxvec_copy(dst_sv, src_sv);
    polxvec_init_subvec2(src_sv, svtildex, s123_len, 1, s45_len);
    polxvec_init_subvec2(dst_sv, sxl, pp->off[Z1S40], 1, s45_len);
    polxvec_copy(dst_sv, src_sv);
    polxvec_init_subvec2(src_sv, svtildex, pp->slen, 1, pp->silen[5]);
    polxvec_init_subvec2(dst_sv, sxl, pp->off[Z1LO] + pp->silen[2], 1, pp->silen[5]);
    polxvec_copy(dst_sv, src_sv);
    polxvec_init_subvec2(src_sv, svtildex, pp->stildelen, 1, pp->vtildelen);
    polxvec_init_subvec2(dst_sv, sxl, pp->off[Z1V10], 1, pp->vtildelen);
    polxvec_copy(dst_sv, src_sv);

    // fill xbin subparts into sxl
    polxvec_init_subvec2 (sv, sxl, pp->off[TSHAT], 1, pp->len[TSHAT]);
    polxvec_frompolyvec (sv, sout + pp->off[TSHAT], 1, pp->len[TSHAT], 1);
    polxvec_init_subvec2 (sv, sxl, pp->off[TVHAT], 1, pp->len[TVHAT]);
    polxvec_frompolyvec (sv, sout + pp->off[TVHAT], 1, pp->len[TVHAT], 1);
    polxvec_init_subvec2 (sv, sxl, pp->off[V0HAT], 1, pp->len[V0HAT]);
    polxvec_frompolyvec (sv, sout + pp->off[V0HAT], 1, pp->len[V0HAT], 1);

    // build sxq[] from sxl (merged layout; gaussian slots stay zero during prove)
    polxvec_init_subvec2(sxq[Z1S10], sxl, pp->off[Z1S10], 1, pp->silen[0]);
    polxvec_init_subvec2(sxq[Z1S20], sxl, pp->off[Z1S20], 1, pp->silen[1]);
    polxvec_init_subvec2(sxq[Z1LO],  sxl, pp->off[Z1LO],  1, pp->silen[2]);
    polxvec_init_subvec2(sxq[Z1S40], sxl, pp->off[Z1S40], 1, pp->silen[3]);
    polxvec_init_subvec2(sxq[Z1S50], sxl, pp->off[Z1S50], 1, pp->silen[4]);
    polxvec_init_subvec2(sxq[Z1V10], sxl, pp->off[Z1V10], 1, pp->vtildelen / 2);
    polxvec_init_subvec2(sxq[Z1V20], sxl, pp->off[Z1V20], 1, pp->vtildelen / 2);
    polxvec_init_subvec2(sxq[Z1S11], sxl, pp->off[Z1S11], 1, pp->silen[0]);
    polxvec_init_subvec2(sxq[Z1S21], sxl, pp->off[Z1S21], 1, pp->silen[1]);
    polxvec_init_subvec2(sxq[Z1HI],  sxl, pp->off[Z1HI],  1, pp->silen[2]);
    polxvec_init_subvec2(sxq[Z1S41], sxl, pp->off[Z1S41], 1, pp->silen[3]);
    polxvec_init_subvec2(sxq[Z1S51], sxl, pp->off[Z1S51], 1, pp->silen[4]);
    polxvec_init_subvec2(sxq[Z1V11], sxl, pp->off[Z1V11], 1, pp->vtildelen / 2);
    polxvec_init_subvec2(sxq[Z1V21], sxl, pp->off[Z1V21], 1, pp->vtildelen / 2);
    polxvec_init_subvec2(sxq[XBIN],  sxl, pp->off[XBIN],  1, pp->xbinlen);

    for (i = 0; i < LIFTS; i++) {
        sparsecnst_eval (hix, zqagg[i], sxq, sxl);
#ifdef DEBUG
        int check;
        check = polxvec_iszero_constcoeff (hix, 0);
        if (check)
            printf ("eq %lu: CT = 0\n", i);
        else
            printf ("eq %lu: CT != 0 ERROR\n", i);
#endif

        polzvec_topolxvec (gx, &g[i], 0, 1, 1);
        polxvec_add (hix, hix, gx); // add uniform mask with ct=0
        polxvec_bindec (&sout[pp->off[HHAT] + i*LOGQ], hix, 1, LOGQ);
    }

    polxvec_init_subvec2 (sv, sxl, pp->off[HHAT], 1, pp->len[HHAT]);
    polxvec_frompolyvec (sv, sout + pp->off[HHAT], 1, pp->len[HHAT], 1);

    // create vanishing constraints

    polxvec_init (ppowers, LOGQ, 1);
    polxvec_init (m1powers, LOGQ, 1);
    polxvec_powers (ppowers, 2, 1, -1); // G2
    polxvec_powers (m1powers, 2, -1, 1); // -G2

    for (i = 0; i < LIFTS; i++) {
        // +G2*gihat
        polxvec_init_subvec2 (phi, zqagg[i]->lin->phi[0], pp->off[Z1LO] + pp->silen[2] + i*LOGQ, 1, LOGQ);
        polxvec_copy (phi, ppowers);
        // -G2*hihat
        polxvec_init_subvec2 (phi, zqagg[i]->lin->phi[0], pp->off[HHAT] + i*LOGQ, 1, LOGQ);
        polxvec_copy (phi, m1powers);
    }

#ifdef DEBUG
    for (i = 0; i < LIFTS; i++) {
        sparsecnst_eval (hix, zqagg[i], sxq, sxl);
        check = polxvec_iszero (hix);
        if (check)
            printf ("eq %lu: POLY = 0\n", i);
        else
            printf ("eq %lu: POLY != 0 ERROR\n", i);
    }
#endif

    // commit U4 = A*hhat

    polxvec_init_subvec (hhatx, tmp1x, 0, 1, pp->len[HHAT]);
    polxvec_frompolyvec (hhatx, &sout[pp->off[HHAT]], 1, pp->len[HHAT], 1);

    polxvec_init_subvec (capu4, tmp2x, 0, 1, pp->kappa_linfmsis);
    commit (capu4, hhatx);
    polzvec_frompolxvec(pi->m[3], capu4, 0, 1, pp->kappa_linfmsis);
    update_hash_polz(ost->h, pi->m[3], pp->kappa_linfmsis);
    //__print_bytes(ost->h, 16);

    // aggregate rq eqs
    sparsecnst finalcnst;

    lnp_aggregate_rq (finalcnst, pp, ist, zqagg, ost->h);
    // Aggregation owns its result; the source constraints are no longer needed.
    for (i = 0; i < LIFTS; i++) sparsecnst_free(zqagg[i]);

    ist_shift_positions(ist, pp, -1);

#ifdef DEBUG
    sparsecnst cfinalcnst;
    sparsecnst_copy2 (cfinalcnst, finalcnst, 4*5);

    sparsecnst_eval (hix, finalcnst, sxq, sxl);
        check = polxvec_iszero (hix);
        if (check)
            printf ("FINALCNST OKAY\n");
        else
            printf ("FINALCNST ERROR\n");
    print_sparsecnst (finalcnst);
    print_sparsecnst (cfinalcnst);
#endif

    polxvec_init (g0, 1, 1);
    polxvec_init (g1, 1, 1);
    polxvec_init (sp, 1, 1);
    polxvec_init (u, 1, 1);
    polxvec_init (v, 1, 1);
    polxvec_init (wsy1, pp->kappa_l2msis1, 1);
    polxvec_init (wvy1, pp->kappa_l2msis2, 1);

    polxvec_init_subvec2(yxq[Z1S10], yxl, pp->off[Z1S10], 1, pp->silen[0]);
    polxvec_init_subvec2(yxq[Z1S20], yxl, pp->off[Z1S20], 1, pp->silen[1]);
    polxvec_init_subvec2(yxq[Z1LO],  yxl, pp->off[Z1LO],  1, pp->silen[2]);
    polxvec_init_subvec2(yxq[Z1S40], yxl, pp->off[Z1S40], 1, pp->silen[3]);
    polxvec_init_subvec2(yxq[Z1S50], yxl, pp->off[Z1S50], 1, pp->silen[4]);
    polxvec_init_subvec2(yxq[Z1V10], yxl, pp->off[Z1V10], 1, pp->vtildelen / 2);
    polxvec_init_subvec2(yxq[Z1V20], yxl, pp->off[Z1V20], 1, pp->vtildelen / 2);

    polxvec_init_subvec2 (svcom, comkey, 0, 1, pp->rslen);

rej_loop2_outer:
    // y1: gaussian mask for stilde||vtilde
    if(quil_polzvec_gaussian_private(z1, pp->stildelen + pp->vtildelen, pp->logsd1, seed, nonce++)) { status=1;goto cleanup_late; }
#if NOMASK == 1
    polzvec_setzero (z1, pp->stildelen + pp->vtildelen);
#endif

    // wsy1 = A1s_split * y1s
    polxvec_init_subvec (y1sx, tmp1x, 0, 1, pp->stildelen);
    polzvec_topolxvec (y1sx, z1s, 0, 1, pp->stildelen);
    probe_mask_width(y1sx, z1s, pp->stildelen, pp->logsd1);

    polxvec_init_subvec2(src_sv, y1sx, 0, 1, s123_len);
    polxvec_init_subvec2(dst_sv, yxl, pp->off[Z1S10], 1, s123_len);
    polxvec_copy(dst_sv, src_sv);
    polxvec_init_subvec2(src_sv, y1sx, s123_len, 1, s45_len);
    polxvec_init_subvec2(dst_sv, yxl, pp->off[Z1S40], 1, s45_len);
    polxvec_copy(dst_sv, src_sv);
    polxvec_init_subvec2(src_sv, y1sx, pp->slen, 1, pp->silen[5]);
    polxvec_init_subvec2(dst_sv, yxl, pp->off[Z1LO] + pp->silen[2], 1, pp->silen[5]);
    polxvec_copy(dst_sv, src_sv);

    ck_off = 0;
    polxvec_init_subvec2(s_sv, y1sx, 0, 1, s123_len);
    off = polxvec_sprod_extension(wsy1, comkey, s_sv);
    ck_off += off;
    polxvec_init_subvec2(ck_sv, comkey, ck_off, 1, comkey->len - ck_off);
    polxvec_init_subvec2(s_sv, y1sx, s123_len, 1, s45_len);
    off = polxvec_sprod_extension_add(wsy1, ck_sv, s_sv);
    ck_off += off;
    polxvec_init_subvec2(ck_sv, comkey, ck_off, 1, comkey->len - ck_off);
    polxvec_init_subvec2(s_sv, y1sx, s123_len + s45_len, 1, pp->silen[5]);
    off = polxvec_sprod_extension_add(wsy1, ck_sv, s_sv);
    ck_off += off;
    assert(ck_off == pp->a2soff);

    polxvec_init_subvec (y1vx, tmp1x, 0, 1, pp->vtildelen);
    polzvec_topolxvec (y1vx, z1v, 0, 1, pp->vtildelen);
    probe_mask_width(y1vx, z1v, pp->vtildelen, pp->logsd1);

    polxvec_init_subvec2 (__t, yxl, pp->off[Z1V10], 1, pp->vtildelen);
    polxvec_copy (__t, y1vx); // populate yxl at merged v10|v20 slot

    // wvy1 = A1v * y1v
    off = polxvec_sprod_extension (wvy1, comkey, y1vx);
    assert (off == pp->a2voff);

    // garbage polynomials g0, g1, u (valid until next outer iter)
    polxvec_setzero (g0, 0, 1, 1);
    for (i = 0; i < finalcnst->quad->len; i++) {
        row = finalcnst->quad->rows[i];
        col = finalcnst->quad->cols[i];
        aij = &finalcnst->quad->coeffs[i];

        polxvec_sprod (sp, yxq[row], yxq[col]);
        polxvec_refresh (sp);
        polxvec_polx_mul_add (g0, aij[0], sp);
        polxvec_refresh (g0);
    }

    polxvec_setzero (g1, 0, 1, 1);
    polxvec_init_subvec2 (__t, finalcnst->lin->phi[0], 0, 1, pp->off[Z1S11]);
    polxvec_sprod (g1, __t, yxl);
    polxvec_refresh (g1);
    for (i = 0; i < finalcnst->quad->len; i++) {
        row = finalcnst->quad->rows[i];
        col = finalcnst->quad->cols[i];
        aij = &finalcnst->quad->coeffs[i];

        polxvec_sprod (sp, yxq[row], sxq[col]);
        polxvec_refresh (sp);
        polxvec_sprod_add (sp, sxq[row], yxq[col]);
        polxvec_refresh (sp);
        polxvec_polx_mul_add (g1, aij[0], sp);
        polxvec_refresh (g1);
    }

    polxvec_init_subvec2 (__t, rsvx, 0, 1, pp->rslen);
    polxvec_copy (u, g1);
    polxvec_sprod_add (u, svcom, __t);
    polxvec_bindec (&sout[pp->off[UHAT]], u, 1, LOGQ);

rej_loop2_inner:
    memcpy (tmp_h, ost->h, HASHLEN);

    // y2: gaussian mask for rs||rv
    if(quil_polzvec_gaussian_private(z2, pp->rslen + pp->rvlen, pp->logsd2, seed, nonce++)) { status=1;goto cleanup_late; }
#if NOMASK == 1
    polzvec_setzero (z2, pp->rslen + pp->rvlen);
#endif

    // ws = wsy1 + A2s * y2s
    polxvec_init_subvec (y2sx, tmp1x, 0, 1, pp->rslen);
    polzvec_topolxvec (y2sx, z2s, 0, 1, pp->rslen);
    probe_mask_width(y2sx, z2s, pp->rslen, pp->logsd2);
    polxvec_copy (y2sx_bak, y2sx);

    polxvec_init_subvec (wsx, tmp2x, 0, 1, pp->kappa_l2msis1);
    polxvec_copy (wsx, wsy1);
    polxvec_sprod_extension_add (wsx, capa2s, y2sx);
    polxvec_bindec (&sout[pp->off[WSHAT]], wsx, pp->kappa_l2msis1, LOGQ);

    polxvec_init_subvec (y2vx, tmp1x, 0, 1, pp->rvlen);
    polzvec_topolxvec (y2vx, z2v, 0, 1, pp->rvlen);
    probe_mask_width(y2vx, z2v, pp->rvlen, pp->logsd2);

    polxvec_init_subvec (wvx, tmp2x, 0, 1, pp->kappa_l2msis2);
    polxvec_copy (wvx, wvy1);
    polxvec_sprod_extension_add (wvx, capa2v, y2vx);
    polxvec_bindec (&sout[pp->off[WVHAT]], wvx, pp->kappa_l2msis2, LOGQ);

    polxvec_copy (v, g0);
    polxvec_sprod_add (v, svcom, y2sx_bak);
    polxvec_bindec (&sout[pp->off[VHAT]], v, 1, LOGQ);

    // commit U5 = A*(wshat,wvhat,uhat,vhat) = A*u5vec
    off = 0;
    polxvec_init_subvec (u5vecx, tmp1x, off, 1, pp->len[WSHAT]);
    polxvec_frompolyvec (u5vecx, &sout[pp->off[WSHAT]], 1, pp->len[WSHAT], 1);
    off += pp->len[WSHAT];
    polxvec_init_subvec (u5vecx, tmp1x, off, 1, pp->len[WVHAT]);
    polxvec_frompolyvec (u5vecx, &sout[pp->off[WVHAT]], 1, pp->len[WVHAT], 1);
    off += pp->len[WVHAT];
    polxvec_init_subvec (u5vecx, tmp1x, off, 1, pp->len[UHAT]);
    polxvec_frompolyvec (u5vecx, &sout[pp->off[UHAT]], 1, pp->len[UHAT], 1);
    off += pp->len[UHAT];
    polxvec_init_subvec (u5vecx, tmp1x, off, 1, pp->len[VHAT]);
    polxvec_frompolyvec (u5vecx, &sout[pp->off[VHAT]], 1, pp->len[VHAT], 1);
    off += pp->len[VHAT];

    len = pp->len[WSHAT] + pp->len[WVHAT] + pp->len[UHAT] + pp->len[VHAT];
    polxvec_init_subvec (u5vecx, tmp1x, 0, 1, len);
    polxvec_init_subvec (capu5, tmp2x, 0, 1, pp->kappa_linfmsis);
    commit (capu5, u5vecx);
    polzvec_frompolxvec(pi->m[4], capu5, 0, 1, pp->kappa_linfmsis);
    update_hash_polz(tmp_h, pi->m[4], pp->kappa_linfmsis);

    // sample challange
    sample_chalx_amortize(&cx, 1, tmp_h);

    // z2 = y2 + c*(rs,rv)
    polxvec_init_subvec (crsvx, tmp1x, 0, 1, pp->rslen + pp->rvlen);
    polxvec_init_subvec (z2x, tmp2x, 0, 1, pp->rslen + pp->rvlen);

    polxvec_polx_mul (crsvx, cx, rsvx);
    polxvec_refresh (crsvx);
    polzvec_topolxvec (z2x, z2, 0, 1, pp->rslen + pp->rvlen);
    polxvec_add (z2x, z2x, crsvx);

    polzvec_frompolxvec (crsv, crsvx, 0, 1, pp->rslen + pp->rvlen);
    polzvec_center (crsv, pp->rslen + pp->rvlen);
    polzvec_frompolxvec (z2, z2x, 0, 1, pp->rslen + pp->rvlen);
    polzvec_center (z2, pp->rslen + pp->rvlen);

    sprod_zv = polzvec_sprodz (z2, crsv, pp->rslen + pp->rvlen);
    sprod_vv = polzvec_sprodz (crsv, crsv, pp->rslen + pp->rvlen);
    reject = quil_rejection_decide_sd_256_stream(&private_stream,1, sprod_zv, sprod_vv, pp->sd2, pp->capm2);
    if (reject < 0) { status = 1; goto cleanup_late; }
    if (reject) {
#if !NOREJ
        // printf("z2 rejected: <v,v>=%ld <z,pv>=%ld\n", sprod_vv, sprod_zv);
        goto rej_loop2_inner;
#endif
    }

    // sample z1 = y1 + c*(stilde,vtilde)
    polxvec_init_subvec (csvtildex, tmp1x, 0, 1, pp->stildelen + pp->vtildelen);
    polxvec_init_subvec (z1x, tmp2x, 0, 1, pp->stildelen + pp->vtildelen);

    polxvec_polx_mul (csvtildex, cx, svtildex);
    polxvec_refresh (csvtildex);
    polzvec_topolxvec (z1x, z1, 0, 1, pp->stildelen + pp->vtildelen);
    polxvec_add (z1x, z1x, csvtildex);

    polzvec_frompolxvec (csvtilde, csvtildex, 0, 1, pp->stildelen + pp->vtildelen);
    polzvec_center (csvtilde, pp->stildelen + pp->vtildelen);
    polzvec_frompolxvec (z1, z1x, 0, 1, pp->stildelen + pp->vtildelen);
    polzvec_center (z1, pp->stildelen + pp->vtildelen);

    sprod_zv = polzvec_sprodz (z1, csvtilde, pp->stildelen + pp->vtildelen);
    sprod_vv = polzvec_sprodz (csvtilde, csvtilde, pp->stildelen + pp->vtildelen);
    reject = quil_rejection_decide_sd_256_stream(&private_stream,0, sprod_zv, sprod_vv, pp->sd1, pp->capm1);
    if (reject < 0) { status = 1; goto cleanup_late; }
#if !NOREJ
    if (reject) {
        // printf("z1 rejected: <v,v>=%ld <z,pv>=%ld\n", sprod_vv, sprod_zv);
        goto rej_loop2_outer;
    }
#endif

    memcpy (ost->h, tmp_h, HASHLEN); // save hash of accepted challange

    // check f'(z) = c^2*f(w)+cg1+g0 before decomposition
#if 1
#if 0
    polxvec zxl, zxq[NWIT], ev1, ev2;
#endif
#if 0
    // create f' by scaling terms of f
    // scale linear part by c that corresponds to stilde,vtilde,rs,rv
    // scale linear part by c^2 that corresponds to xbin
    // (xbin is not part of the masked openings)
    // scale constant term by c^2

    polxvec_polx_mul (cfinalcnst->lin->phi[0], cx, cfinalcnst->lin->phi[0]);
    polxvec_refresh (cfinalcnst->lin->phi[0]);
    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], pp->wtlen - pp->xbinlen, 1, pp->xbinlen);
    polxvec_polx_mul (__t, cx, __t);
    polxvec_refresh (__t);

    polxvec_polx_mul (cfinalcnst->b, cx, cfinalcnst->b);
    polxvec_refresh (cfinalcnst->b);
    polxvec_polx_mul (cfinalcnst->b, cx, cfinalcnst->b);
    polxvec_refresh (cfinalcnst->b);

    sparsecnst_refresh (cfinalcnst);
#endif
#if 0
    polxvec_init (zxl, pp->wtlen, 1);
    polxvec_init (ev1, 1, 1);
    polxvec_init (ev2, 1, 1);

    off = 0;
    for (i = 0; i < XBIN; i++) {
        polxvec_init_subvec2(zxq[i], zxl, off, 1, pp->len[i]);
        off += pp->len[i];
    }
    polxvec_init_subvec2(zxq[XBIN], zxl, off, 1, pp->xbinlen);

    // need v0 from xbin.. more ?
    polxvec_frompolyvec (zxl, sout, 1, pp->wtlen, 1);
    // zi not in polyvec until decomp, want to check before!
    polzvec_topolxvec (zxl, z1, 0, 1, pp->stildelen + pp->vtildelen);
    polzvec_topolxvec (zxl, z2, 2 * (pp->stildelen + pp->vtildelen), 1, pp->rslen + pp->rvlen);

    // c^2*f(w)+cg1+g0
    sparsecnst_eval (ev1, finalcnst, sxq, sxl);
    polxvec_polx_mul (ev1, cx, ev1);
    polxvec_refresh (ev1);
    polxvec_polx_mul (ev1, cx, ev1);
    polxvec_refresh (ev1);
    
    polxvec_polx_mul_add (ev1, cx, g1);
    polxvec_refresh (ev1);
    polxvec_add (ev1, ev1, g0);

    //if (polxvec_iszero (ev1) == 0)
    //    printf ("c^2*f(w)+cg1+g0 NOT zero\n");
    //else
    //    printf ("c^2*f(w)+cg1+g0 is zero\n");
    
    // f'(z)
    sparsecnst_eval (ev2, cfinalcnst, zxq, zxl);

    //if (polxvec_iszero (ev2) == 0)
    //    printf ("f'(z) NOT zero\n");
    //else
    //    printf ("f'(z) is zero\n");

    // f'(z) == c^2*f(w)+cg1+g0
    polxvec_sub (ev1, ev1, ev2);
    if (polxvec_iszero (ev1) == 0) {
        polz res[1];
        printf ("ERRROR\n");
        polzvec_frompolxvec (res, ev1, 0, 1, 1);
        polz_printint64 (res[0]);
    }

    // f'(z) - cg1 - g0 == 0
    polxvec_neg (g1, g1); // -g1
    polxvec_neg (g0, g0); // -g0
    polxvec_polx_mul_add (ev2, cx, g1);
    polxvec_add (ev2, ev2, g0); // f'(z)-c*g1-g0
    if (polxvec_iszero (ev2) == 0) {
        printf ("ERROR\n");
    }

    // f'(z) - cu - v + A*z2s == 0
    sparsecnst_eval (ev2, cfinalcnst, zxq, zxl); // recompute f'(z)
    polxvec_neg (u, u); // -u
    polxvec_neg (v, v); // -u
    polxvec_polx_mul_add (ev2, cx, u);
    polxvec_add (ev2, ev2, v);
    // z2 position in internal layout for DEBUG
    polxvec_init_subvec2 (__t, zxl, 2 * (pp->stildelen + pp->vtildelen), 1, pp->rslen);
    polxvec_sprod_add (ev2, svcom, __t);

    if (polxvec_iszero (ev2) == 0) {
        printf ("ERROR\n");
    }
#endif
#if 0
    polxvec powers;
    polxvec_init (powers, LOGQ, 1);
    polxvec_powers (powers, 2, -1, 1); // -G2

    // convert above to verifier check (take u,v,z2s from witness)
    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], pp->off[Z1LO] + pp->silen[2] + pp->silen[5], 1, pp->rslen);
    polxvec_copy (__t, svcom); // +A*z2s

    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], pp->off[VHAT], 1, pp->len[UHAT]);
    polxvec_copy (__t, powers); // -G2*vhat

    polxvec_polx_mul(powers, cx, powers); // -c*G2*uhat
    polxvec_refresh (powers);
    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], pp->off[UHAT], 1, pp->len[UHAT]);
    polxvec_copy (__t, powers);

    polxvec_free (powers);
#endif
#if 0
    sparsecnst_eval (ev2, cfinalcnst, zxq, zxl);
    if (polxvec_iszero (ev2) == 0) {
        printf ("ERROR\n");
    }
#endif


#endif

    // copy decomposed z1 and z2 to sout (merged output layout).
    // z1 is in natural order (s1|s2|s3|s4|s5|s6|v10|v20); positions are cumulative.
    // stride = distance between uniform (Z1S10..Z1V20) and gaussian (Z1S11..Z1V21) blocks.
    stride = pp->off[Z1S11];
    z1lo_out = pp->off[Z1LO];
    z1_pos = 0;
    polzvec_decompose(sout + pp->off[Z1S10], z1 + z1_pos, pp->silen[0], stride, 2, pp->b1); z1_pos += pp->silen[0];
    polzvec_decompose(sout + pp->off[Z1S20], z1 + z1_pos, pp->silen[1], stride, 2, pp->b1); z1_pos += pp->silen[1];
    polzvec_decompose(sout + z1lo_out,       z1 + z1_pos, pp->silen[2], stride, 2, pp->b1); z1_pos += pp->silen[2];
    z1lo_out += pp->silen[2];
    polzvec_decompose(sout + pp->off[Z1S40], z1 + z1_pos, pp->silen[3], stride, 2, pp->b1); z1_pos += pp->silen[3];
    polzvec_decompose(sout + pp->off[Z1S50], z1 + z1_pos, pp->silen[4], stride, 2, pp->b1); z1_pos += pp->silen[4];
    polzvec_decompose(sout + z1lo_out,       z1 + z1_pos, pp->silen[5], stride, 2, pp->b1); z1_pos += pp->silen[5];
    z1lo_out += pp->silen[5];
    polzvec_decompose(sout + pp->off[Z1V10], z1 + z1_pos, pp->vtildelen / 2, stride, 2, pp->b1); z1_pos += pp->vtildelen / 2;
    polzvec_decompose(sout + pp->off[Z1V20], z1 + z1_pos, pp->vtildelen / 2, stride, 2, pp->b1); z1_pos += pp->vtildelen / 2;
    assert(z1_pos == pp->stildelen + pp->vtildelen);
    // z2 -> Z1LO after s3+s6, base b2 instead of b1
    polzvec_decompose(sout + z1lo_out, z2, pp->rslen + pp->rvlen, stride, 2, pp->b2);

#ifdef DEBUG
    // update z1
    polxvec_frompolyvec (zxl, sout, 1, 2 * (pp->stildelen + pp->vtildelen), 1);
#endif

#if 0
    // adapt verifier check to z1 split (quad terms)
    const int64_t b1 = (int64_t)1 << pp->b1; 
    polx aijb1, aijb1sq;
    j = 5;
    for (i = 0; i < 5; i++) {
        row = cfinalcnst->quad->rows[i];
        col = cfinalcnst->quad->cols[i];
        aij = &cfinalcnst->quad->coeffs[i];

        polx_scale (aijb1, aij[0], b1);
        polx_refresh (aijb1);
        polx_scale (aijb1sq, aijb1, b1);
        polx_refresh (aijb1sq);

        cfinalcnst->quad->rows[j] = row + Z1S11;
        cfinalcnst->quad->cols[j] = col + Z1S11;
        polx_copy (cfinalcnst->quad->coeffs[j], aijb1sq);
        j++;

        cfinalcnst->quad->rows[j] = row;
        cfinalcnst->quad->cols[j] = col + Z1S11;
        polx_copy (cfinalcnst->quad->coeffs[j], aijb1);
        j++;

        cfinalcnst->quad->rows[j] = row + Z1S11;
        cfinalcnst->quad->cols[j] = col;
        polx_copy (cfinalcnst->quad->coeffs[j], aijb1);
        j++;
    }

    // adapt verifier check to z1 split (lin terms)
    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], 0, 1, pp->stildelen + pp->vtildelen);
    polxvec_init_subvec2 (__s, cfinalcnst->lin->phi[0], pp->stildelen + pp->vtildelen, 1, pp->stildelen + pp->vtildelen);
    polxvec_scale (__s, __t, b1);
    polxvec_refresh (__s);

    cfinalcnst->quad->len = j;
    sparsecnst_refresh (cfinalcnst);
#endif

#ifdef DEBUG
    //print_sparsecnst (cfinalcnst);

    sparsecnst_eval (ev2, cfinalcnst, zxq, zxl);
    if (polxvec_iszero (ev2) == 0) {
        printf ("ERRRORRRRRRRRRRRRRRRRRRRRR 6\n");
    }

    polxvec_free (zxl);
    polxvec_free (ev1);
    polxvec_free (ev2);
#endif

    // add verification checks

    lnp_addchecks (ost, pp, pi, cx, finalcnst);
cleanup_late:
    sparsecnst_free(finalcnst);
    polxvec_free (g0);
    polxvec_free (g1);
    polxvec_free (u);
    polxvec_free (v);
    polxvec_free (yxl);
    polxvec_free (y2sx_bak);
    polxvec_free (sp);
    polxvec_free (wsy1);
    polxvec_free (wvy1);

    polxvec_free (ppowers);
    polxvec_free (m1powers);
    polxvec_free (hix);
    polxvec_free (gx);
    polxvec_free (sxl);
cleanup_early:
    polxvec_free(tmp1x);
    polxvec_free(tmp2x);
    polxvec_free(iwtx);
    polxvec_free(svtildex);
    polxvec_free(rsvx);
    free(jlmat1);
    free(jlmat3);
    free (csvtilde);
    free (crsv);
    free (z1);
    free (z2);

    quil_prg_clear(seed,sizeof(seed));
    quil_prg_clear(&state,sizeof(state));
    quil_prg_clear(umaskbytes,sizeof(umaskbytes));
    return status;
}

static void lnp_addcheck_finalcnst (sparsecnst cfinalcnst, polx cx, const sparsecnst finalcnst, const lnp_params pp) {
    polxvec __t, __s, svcom;
    size_t i, j, row, col;
    size_t z1_blk1_len, z1_blk2_len;
    polx *aij;

    polxvec_init_subvec2 (svcom, comkey, 0, 1, pp->rslen);

    // create f' by scaling terms of f
    // scale linear part by c that corresponds to stilde,vtilde,rs,rv
    // scale linear part by c^2 that corresponds to xbin
    // (xbin is not part of the masked openings)
    // scale constant term by c^2
    sparsecnst_copy2 (cfinalcnst, finalcnst, 4*5);

    // phi[0] already matches the output layout because sxl uses merged layout
    // and ist positions were translated on the fly during aggregation.
    polxvec_polx_mul (cfinalcnst->lin->phi[0], cx, cfinalcnst->lin->phi[0]);
    quil_polxvec_parallel_refresh (cfinalcnst->lin->phi[0]);
    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], pp->wtlen - pp->xbinlen, 1, pp->xbinlen);
    polxvec_polx_mul (__t, cx, __t);
    quil_polxvec_parallel_refresh (__t);

    polxvec_polx_mul (cfinalcnst->b, cx, cfinalcnst->b);
    polxvec_refresh (cfinalcnst->b);
    polxvec_polx_mul (cfinalcnst->b, cx, cfinalcnst->b);
    polxvec_refresh (cfinalcnst->b);

    // Every component is canonical here: the quadratic coefficients were
    // refreshed with finalcnst, and phi[0] and b were refreshed above. The
    // slices written below are refreshed individually, so the whole-constraint
    // refresh the original performed here is omitted (refresh is idempotent).

    polxvec powers;
    polxvec_init (powers, LOGQ, 1);
    polxvec_powers (powers, 2, -1, 1); // -G2

    // z2s output position: within Z1LO after s3+s6
    size_t z2s_out = pp->off[Z1LO] + pp->silen[2] + pp->silen[5];

    // convert above to verifier check (take u,v,z2s from witness)
    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], z2s_out, 1, pp->rslen);
    polxvec_copy (__t, svcom); // +A*z2s
    polxvec_refresh (__t);

    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], pp->off[VHAT], 1, pp->len[UHAT]);
    polxvec_copy (__t, powers); // -G2*vhat
    polxvec_refresh (__t);

    polxvec_polx_mul(powers, cx, powers); // -c*G2*uhat
    polxvec_refresh (powers);
    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], pp->off[UHAT], 1, pp->len[UHAT]);
    polxvec_copy (__t, powers);
    polxvec_refresh (__t);

    polxvec_free (powers);

    // adapt verifier checks to z2 split (lin terms, z2 does not appear in quad terms)
    // z2_0 is at z2s_out in Z1LO, z2_1 is at corresponding Z1HI position
    const int64_t b2 = (int64_t)1 << pp->b2;
    size_t z2_out_0 = z2s_out;
    size_t z2_out_1 = pp->off[Z1HI] + pp->silen[2] + pp->silen[5];

    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], z2_out_0, 1, pp->rslen + pp->rvlen);
    polxvec_init_subvec2 (__s, cfinalcnst->lin->phi[0], z2_out_1, 1, pp->rslen + pp->rvlen);
    polxvec_scale (__s, __t, b2);
    quil_polxvec_parallel_refresh (__s);

    // adapt verifier check to z1 split (quad terms)
    const int64_t b1 = (int64_t)1 << pp->b1;
    polx aijb1, aijb1sq;
    size_t nquad = cfinalcnst->quad->len;
    j = nquad;
    for (i = 0; i < nquad; i++) {
        row = cfinalcnst->quad->rows[i];
        col = cfinalcnst->quad->cols[i];
        aij = &cfinalcnst->quad->coeffs[i];

        polx_scale (aijb1, aij[0], b1);
        polx_refresh (aijb1);
        polx_scale (aijb1sq, aijb1, b1);
        polx_refresh (aijb1sq);

        cfinalcnst->quad->rows[j] = row + Z1S11;
        cfinalcnst->quad->cols[j] = col + Z1S11;
        polx_copy (cfinalcnst->quad->coeffs[j], aijb1sq);
        j++;

        cfinalcnst->quad->rows[j] = row;
        cfinalcnst->quad->cols[j] = col + Z1S11;
        polx_copy (cfinalcnst->quad->coeffs[j], aijb1);
        j++;

        cfinalcnst->quad->rows[j] = col;
        cfinalcnst->quad->cols[j] = row + Z1S11;
        polx_copy (cfinalcnst->quad->coeffs[j], aijb1);
        j++;
    }

    // adapt verifier check to z1 split (lin terms)
    // split into two blocks to skip z2 (which uses b2, already handled above)
    // block 1: s1+s2+s3+s6 (contiguous in output)
    z1_blk1_len = pp->silen[0]+pp->silen[1]+pp->silen[2]+pp->silen[5];
    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], pp->off[Z1S10], 1, z1_blk1_len);
    polxvec_init_subvec2 (__s, cfinalcnst->lin->phi[0], pp->off[Z1S11], 1, z1_blk1_len);
    polxvec_scale (__s, __t, b1);
    quil_polxvec_parallel_refresh (__s);
    // block 2: s4+s5+v10+v20 (contiguous in output)
    z1_blk2_len = pp->silen[3]+pp->silen[4]+pp->vtildelen;
    polxvec_init_subvec2 (__t, cfinalcnst->lin->phi[0], pp->off[Z1S40], 1, z1_blk2_len);
    polxvec_init_subvec2 (__s, cfinalcnst->lin->phi[0], pp->off[Z1S41], 1, z1_blk2_len);
    polxvec_scale (__s, __t, b1);
    quil_polxvec_parallel_refresh (__s);

    cfinalcnst->quad->len = j;
    // The extended quadratic coefficients, b and every written phi slice are
    // canonical; the original whole-constraint refresh here would recompute
    // identical values and widths.
}

static void lnp_addchecks(statement ost, const lnp_params pp, const lnp_proof pi,
                          polx chalx, sparsecnst finalcnst) {
    // sparsecnst: 1 final quad eq check
    // comcnst: 4 outer commitments + 2 masked opening relations
    rqcnstset_init(ost->rqcnst, 1, 4 + 2);
    ost->rqcnst->sparse_nchal = 1;
    ost->rqcnst->com_nchal = 4 + pp->kappa_l2msis1 + pp->kappa_l2msis2; // assumes msislinf rank is 1

    quil_resource_trace("lnp_checks_final_begin");
    lnp_addcheck_finalcnst (ost->rqcnst->sparse[0], chalx, finalcnst, pp);
    quil_resource_trace("lnp_checks_final_end");

    lnp_addcheck_commmit (&ost->rqcnst->com[0], pp, pi);

    lnp_addcheck_sopening (ost->rqcnst->com[4], pp, chalx);
    lnp_addcheck_vopening (ost->rqcnst->com[5], pp, chalx);

    // pre-allocate additional 1 sparse and 1 sigmam1 cnst for
    // for binary compiler
    zqcnstset_init(ost->zqcnst, LIFTS, LIFTS + 1, 0, 0 + 1, 0);
    ost->zqcnst->sparse_nchal = LIFTS;

    lnp_addcheck_lift_zero_coeff (ost->zqcnst->sparse, pp->off[HHAT]);
}

// round the standard deviations that will be sampled
// to closest value of the form 1.55*2^log2sd and adjust gammas
static int _get_params_rejstd (long double *capm, unsigned int *log2sd, long double *sd,
                                  long double *gamma, long double t) {
    return quil_private_sampling_params(capm, log2sd, sd, gamma, t, 0);
}

// round the standard deviations that will be sampled
// to closest value of the form 1.55*2^log2sd and adjust gammas
static int _get_params_rejsgnleak (long double *capm, unsigned int *log2sd, long double *sd,
                                    long double *gamma, long double t) {
    return quil_private_sampling_params(capm, log2sd, sd, gamma, t, 1);
}

int lnp_params_gen (lnp_params outpp, size_t *pibits, size_t *owtbits, const statement st) {
    long double gammap = 16;
    long double gamma1 = 8;
    long double gamma2 = 4;
    long double sibeta[5 + 1]; 
    long double sdp, capmp, sum;
    long double sd1, capm1;
    long double sd2, capm2;
    long double capt;
    unsigned int logsdp, logsd1, logsd2;
    uint64_t betassq;
    long double beta_l2msis1, tmp;
    long double beta_linfmsis_l2, beta_l2msis2;
    size_t silen[5 + 1], v0ihatlen[LNP_NPROJ], k[LNP_NPROJ];
    size_t slen, rslen, srslen, ghatlen, yhatlen, kappa_linfmsis;
    size_t kappa_l2msis1, kappa_l2msis2, rvlen;
    size_t silen_max, off, stildelen, vtildelen;
    size_t tshatlen, tvhatlen, hhatlen, wshatlen, wvhatlen, uhatlen, whatlen, umaskhatlen;
    size_t b1, b2, v0hatlen;
    uint64_t beta_linfmsis;
    uint64_t z1s0betasq[6];
    uint64_t z1s1betasq[6];
    uint64_t z1v0betasq;
    uint64_t z1v1betasq;
    uint64_t deg;
    size_t a2soff, a2voff;
    size_t wtlen, xbinlen;
    size_t s6betasq;
    size_t s123_ck, s45_ck; // extension-aligned A1 sub-block lengths
    int i, ret;

    ret = 1;
    memset(outpp, 0, sizeof(*outpp));

    // witness must be of the form
    // s1=z0, s2=z1, s3=that||ghat||hhat, s4=xbin, s5=sigmam1(xbin)
    assert(st->r == 5);
    assert(st->normty[0] == L2APPROX);
    assert(st->normty[1] == L2APPROX);
    assert(st->normty[2] == L2APPROX);
    assert(st->normty[3] == BIN);
    assert(st->normty[4] == L2APPROX);

    // rs uniform binary randomness
    rslen = KAPPA_MLWE;
    // rv uniform binary randomness
    rvlen = KAPPA_MLWE;

    // s1,..,s5
    for (i = 0; i < 5; i++)
        silen[i] = st->n[i];

    // si norm bounds
    for (i = 0; i < 5; i++)
        sibeta[i] = sqrtl(st->normsq[i]);

    // masks uniform mod 2^k in [2^(k-1),..,2^(k-1)-1]
    for (i = 0; i < LNP_NPROJ; i++)
        k[i] = ceill(log2l(JL_INF_MULT * sibeta[i]));

    // params for second projection
    capt = sqrtl(JL_L2_MULT * LNP_NPROJ * LNP_MAXCARRIES);
    sdp = gammap * capt;
    if (_get_params_rejstd (&capmp, &logsdp, &sdp, &gammap, capt)) goto ret;
    silen_max = silen[0]; // max len s1,..,s4
    for (i = 1; i < LNP_NPROJ; i++)
        silen_max = silen[i] > silen_max ? silen[i] : silen_max;

    // s6 = (ghat,yhat,umaskhat)
    // bindec of masking polys: g uniform with ct=0,
    // y gaussian, umask uniform mod 2^k
    ghatlen = LOGQ * LIFTS;
    yhatlen = (logsdp + YHAT_EXTRA_BITS) * 256 / N;
    umaskhatlen = 0;
    for (i = 0; i < LNP_NPROJ; i++)
        umaskhatlen += k[i] * 256 / N;
    silen[5] = ghatlen + yhatlen + umaskhatlen;

    // use a tighter bound on s6 than the naive sibeta[5] = sqrtl(silen[5] * N);
    s6betasq = LIFTS * (N - 1) * LOGQ; // l2sqr(ghat)
    s6betasq += (256 / N) * N * (logsdp + YHAT_EXTRA_BITS); // l2sqr(yhat)
    for (i = 0; i < LNP_NPROJ; i++)
        s6betasq += N * k[i]; // l2sqr(umaskhat)
    sibeta[5] = sqrtl(s6betasq);

    // s = (s1,..,s5)
    slen = 0;
    for (i = 0; i < 5; i++) {
        slen += silen[i];
    }
    // stilde = (s1,..,s6)
    stildelen = slen + silen[5];

    // srs = (stilde,rs)
    srslen = stildelen + rslen;

    v0hatlen = 0;
    for (i = 0; i < LNP_NPROJ; i++) {
        v0ihatlen[i] = k[i] * 256 / N;
        v0hatlen += v0ihatlen[i];
    }

    // v1[i] = w[i]-t[i]
    // vtilde = (v[i],t[i],sigmam1(v[i]),simgam1(t[i]))
    vtildelen = 256 / N * LNP_NPROJ * 2 * 2;

    // standard deviation for mask y1: z1 = y1 + c*(stilde,vtilde)
    betassq = 0;
    for (i = 0; i < 5; i++)
        betassq += st->normsq[i];
    betassq += s6betasq; // s6
    betassq += 2 * LNP_NPROJ * LNP_MAXCARRIES;
    sd1 = gamma1 * T * sqrtl(betassq);
    if (_get_params_rejstd (&capm1, &logsd1, &sd1, &gamma1, T * sqrtl(betassq))) goto ret;
    
    // standard deviation for mask y2: z2 = y2 + c*(rs,rv)
    sd2 = gamma2 * T * sqrtl(N * rslen + N * rvlen);
    if (_get_params_rejsgnleak (&capm2, &logsd2, &sd2, &gamma2, T * sqrtl(N * rslen + N * rvlen))) goto ret;

    // decomposition base for z1=(z1s,z1v)
    b1 = floorl((log2l(12) + log2l(sd1 * sd1)) / 4); // floor round ceil ?
    // decomposition base for z2=(z2s,z2v)
    b2 = floorl((log2l(12) + log2l(sd2 * sd2)) / 4); // floor round ceil ?

    // take both bases to be the maximum (because the merge puts elements of both bases in one part)
    b1 = MAX (b1, b2);
    b2 = b1;

    for (i = 0; i < 6; i++) {
        z1s0betasq[i] = normsq_u (silen[i] * N, b1);
        z1s1betasq[i] = normsq_g (silen[i] * N, b1, sd1);
    }
    // merge s6 and z2 norms into betasq[2] (Z1LO = s3||s6||z2)
    z1s0betasq[2] += z1s0betasq[5] + normsq_u ((rslen + rvlen) * N, b2);
    z1s1betasq[2] += z1s1betasq[5] + normsq_g ((rslen + rvlen) * N, b2, sd2);
    z1v0betasq = normsq_u (vtildelen / 2 * N, b1);
    z1v1betasq = normsq_g (vtildelen / 2 * N, b1, sd1);

    // msis linf <= 2 hardness
    beta_linfmsis = 2;

    kappa_linfmsis = 1;
    beta_linfmsis_l2 = sqrtl(kappa_linfmsis * N * (beta_linfmsis * beta_linfmsis));
    while (!sis_secure(kappa_linfmsis, beta_linfmsis_l2)) {
        kappa_linfmsis++;
        beta_linfmsis_l2 = sqrtl(kappa_linfmsis * N * (beta_linfmsis * beta_linfmsis));
        if (kappa_linfmsis >= 1) { // U1,U2,U4,U5 1 poly each
            goto ret;
        }
    }

    // msis l2 hardness 1
    // betasq[2] already includes s6+z2 norms

    sum = 0;
    for (i = 0; i < 5; i++) {
        tmp = sqrtl(z1s0betasq[i]) + sqrtl(z1s1betasq[i])*(1ULL<<b1);
        sum += tmp * tmp;
    }
    beta_l2msis1 = 8 * T * sqrtl(sum) * JL_INF_SLACK;

    kappa_l2msis1 = 1;
    while (!sis_secure(kappa_l2msis1, beta_l2msis1)) {
        kappa_l2msis1++;
        if (kappa_l2msis1 >= 4096 / N) {
            goto ret;
        }
    }

    // msis l2 hardness 2
    // z2v is a sub-vector of the merged Z1LO/Z1HI blocks, so its norm is
    // upper-bounded (worst case) by the full merged block norm. Include this
    // upper bound so kappa_l2msis2 covers the actual extractable norm of
    // (z1v, z2v) from the v-opening.

    sum = 0;
    tmp = sqrtl (z1v0betasq) + sqrtl (z1v1betasq)*(1ULL<<b1);
    sum += tmp * tmp;
    tmp = sqrtl (z1s0betasq[2]) + sqrtl(z1s1betasq[2])*(1ULL<<b2);
    sum += tmp * tmp;
    beta_l2msis2 = 8 * T * sqrtl(sum) * JL_INF_SLACK;

    kappa_l2msis2 = 1;
    while (!sis_secure(kappa_l2msis2, beta_l2msis2)) {
        kappa_l2msis2++;
        if (kappa_l2msis2 >= 4096 / N) {
            goto ret;
        }
    }

    // commitment key offsets
    // A = (A1s,A2s), A = (A1v,A2v)
    // a1soff = 0, a1voff = 0
    // extension-aligned comkey layout for split s-commitment:
    // A1 = (A1_s123 | A1_s45 | A1_s6), each block extension-ring-aligned
    deg = next2power (kappa_l2msis1);
    s123_ck = silen[0] + silen[1] + silen[2];
    s45_ck = silen[3] + silen[4];
    a2soff = extlen(s123_ck, deg) + extlen(s45_ck, deg) + extlen(silen[5], deg);
    deg = next2power (kappa_l2msis2);
    a2voff = extlen (vtildelen, deg);

    // concat witness structure: offesets and lengths

    tshatlen = kappa_l2msis1 * LOGQ;
    tvhatlen = kappa_l2msis2 * LOGQ;
    // v0hatlen set above
    hhatlen = LIFTS * LOGQ;
    wshatlen = kappa_l2msis1 * LOGQ;
    wvhatlen = kappa_l2msis2 * LOGQ;
    uhatlen = LOGQ;
    whatlen = LOGQ;
    // sum
    xbinlen = tshatlen + tvhatlen + v0hatlen + hhatlen + wshatlen + wvhatlen + uhatlen + whatlen;


    // check conditions on parameters

    if (!(2 * N * silen[3] * (2 * JL_INF_SLACK) * (2 * JL_INF_SLACK) < Q))
        goto ret;
    if (!(2 * sdp * sqrtl(512.0L / 26.0L) * 2048 * 41 < Q))
        goto ret;
    if (!(2 * (2 * sdp * sqrtl(512.0L / 26.0L)) * (2 * sdp * sqrtl(512.0L / 26.0L)) < Q))
        goto ret;
    for (i = 0; i < LNP_NPROJ; i++) {
        if (!((1ULL << k[i]) * 91 / 0.74 < Q))
            goto ret;
    }

    // populate output param struct

    outpp->a2soff = a2soff;
    outpp->a2voff = a2voff;

    // merged Z1LO length = s3 + s6 + z2
    size_t z1lo_len = silen[2] + silen[5] + rslen + rvlen;

    // --- output layout (sout): s1,s2,Z1LO(s3||s6||z2),s4,s5,v10,v20,...,XBIN ---
    off = 0;
    outpp->off[Z1S10] = off; outpp->len[Z1S10] = silen[0]; off += silen[0];
    outpp->off[Z1S20] = off; outpp->len[Z1S20] = silen[1]; off += silen[1];
    outpp->off[Z1LO]  = off; outpp->len[Z1LO]  = z1lo_len; off += z1lo_len;
    outpp->off[Z1S40] = off; outpp->len[Z1S40] = silen[3]; off += silen[3];
    outpp->off[Z1S50] = off; outpp->len[Z1S50] = silen[4]; off += silen[4];
    outpp->off[Z1V10] = off; outpp->len[Z1V10] = vtildelen / 2; off += vtildelen / 2;
    outpp->off[Z1V20] = off; outpp->len[Z1V20] = vtildelen / 2; off += vtildelen / 2;
    outpp->off[Z1S11] = off; outpp->len[Z1S11] = silen[0]; off += silen[0];
    outpp->off[Z1S21] = off; outpp->len[Z1S21] = silen[1]; off += silen[1];
    outpp->off[Z1HI]  = off; outpp->len[Z1HI]  = z1lo_len; off += z1lo_len;
    outpp->off[Z1S41] = off; outpp->len[Z1S41] = silen[3]; off += silen[3];
    outpp->off[Z1S51] = off; outpp->len[Z1S51] = silen[4]; off += silen[4];
    outpp->off[Z1V11] = off; outpp->len[Z1V11] = vtildelen / 2; off += vtildelen / 2;
    outpp->off[Z1V21] = off; outpp->len[Z1V21] = vtildelen / 2; off += vtildelen / 2;

    outpp->off[TSHAT] = off; outpp->len[TSHAT] = tshatlen; off += tshatlen;
    outpp->off[TVHAT] = off; outpp->len[TVHAT] = tvhatlen; off += tvhatlen;
    outpp->off[V0HAT] = off; outpp->len[V0HAT] = v0hatlen; off += v0hatlen;
    outpp->off[HHAT]  = off; outpp->len[HHAT]  = hhatlen;  off += hhatlen;
    outpp->off[WSHAT] = off; outpp->len[WSHAT] = wshatlen; off += wshatlen;
    outpp->off[WVHAT] = off; outpp->len[WVHAT] = wvhatlen; off += wvhatlen;
    outpp->off[UHAT]  = off; outpp->len[UHAT]  = uhatlen;  off += uhatlen;
    outpp->off[VHAT]  = off; outpp->len[VHAT]  = whatlen;   off += whatlen;

    wtlen = 0;
    for (i = 0; i < NPART; i++)
      wtlen += outpp->len[i];
    outpp->wtlen = wtlen;
    outpp->xbinlen = xbinlen;

    outpp->kappa_mlwe = KAPPA_MLWE;

    outpp->kappa_linfmsis = kappa_linfmsis;
    outpp->beta_linfmsis = beta_linfmsis;

    outpp->kappa_l2msis1 = kappa_l2msis1;
    outpp->beta_l2msis1 = beta_l2msis1;

    outpp->kappa_l2msis2 = kappa_l2msis2;
    outpp->beta_l2msis2 = beta_l2msis2;

    for (i = 0; i < 5 + 1; i++) {
        outpp->silen[i] = silen[i];
        outpp->sibeta[i] = sibeta[i];
    }
    outpp->slen = slen;
    outpp->stildelen = stildelen;
    outpp->silen_max = silen_max;

    for (i = 0; i < LNP_NPROJ; i++) {
        outpp->v0ihatlen[i] = v0ihatlen[i];
    }
    outpp->v0hatlen = v0hatlen;
    outpp->vtildelen = vtildelen;

    outpp->sdp = sdp;
    outpp->logsdp = logsdp;
    outpp->gammap = gammap;
    outpp->capmp = capmp;

    outpp->sd1 = sd1;
    outpp->logsd1 = logsd1;
    outpp->gamma1 = gamma1;
    outpp->capm1 = capm1;

    outpp->sd2 = sd2;
    outpp->logsd2 = logsd2;
    outpp->gamma2 = gamma2;
    outpp->capm2 = capm2;

    outpp->rslen = rslen;
    outpp->rvlen = rvlen;

    outpp->b1 = b1;
    outpp->b2 = b2;

    outpp->srslen = srslen;

    for (i = 0; i < LNP_NPROJ; i++) {
        outpp->k[i] = k[i];
    }
    for (i = 0; i < 5; i++) {
        outpp->z1s0betasq[i] = z1s0betasq[i];
        outpp->z1s1betasq[i] = z1s1betasq[i];
    }
    outpp->z1s0betasq[5] = 0; // merged into [2]
    outpp->z1s1betasq[5] = 0;
    outpp->z1v0betasq = z1v0betasq;
    outpp->z1v1betasq = z1v1betasq;

    *owtbits = 0;
    *owtbits += (log2l(sd1 / ((int64_t)1 << b1)) + LOGEDIV2 + b1) * ((stildelen + vtildelen) * N);
    *owtbits += (log2l(sd2 / ((int64_t)1 << b2)) + LOGEDIV2 + b2) * ((rslen + rvlen) * N);
    *owtbits += xbinlen * N;

    *pibits = 0;
    *pibits += (log2l(sdp) + LOGEDIV2) * N; // z
    *pibits += 4 * kappa_linfmsis * N * LOGQ; // U1,U2,U4,U4

    ret = 0;
ret:
    return ret;
}

void lnp_params_free(lnp_params outpp) {
    (void)outpp;
}

void lnp_comkey_init(const lnp_params pp) {
    size_t max = 0;
    size_t lens[6] = {
        pp->a2soff + pp->rslen,
        pp->a2voff + pp->rvlen,
        pp->len[TSHAT], // U1 = A*tshat
        pp->len[TVHAT] + pp->len[V0HAT], // U2 = A*(tvhat,v0hat)
        pp->len[HHAT], // U4 = A*hhat
        pp->len[WSHAT] + pp->len[WVHAT] + pp->len[UHAT]
                  + pp->len[VHAT], // U5 = A*(wshat,wvhat,uhat,vhat)
    };
    int i;

    for (i = 0; i < 6; i++) {
        if (lens[i] > max)
            max = lens[i];
    }
    comkey_init(max);
}

void lnp_witness_init(witness owt, const lnp_params pp) {
    size_t i, r, maxr, nn;

    r = 5 * 2;  // z1s: s1,s2,Z1LO,s4,s5 (s3+s6+z2 merged)
    r += 2 * 2; // z1v: masked vi
    r += 1; // xbin: tshat,tvhat,v0hat,hhat,wshat,wvhat,uhat,vhat

    maxr = r;
    maxr += 1; // sigmam1(xbin)

    assert (r == NWIT);
    assert (maxr == NWIT + 1);

    witness_init (owt, r, maxr);

    // use output lengths from pp->len[]
    for (i = 0; i < NWIT; i++)
        owt->n[i] = pp->len[i];

    owt->n[XBIN] = pp->xbinlen;
    // pre-allocate space for sigmam1(xbin)
    owt->n[XBIN + 1] = owt->n[XBIN];

    nn = 0;
    for(i = 0; i < maxr; i++)
        nn += owt->n[i];

    owt->s[0] = _aligned_alloc(64, nn * sizeof(poly));
    memset(owt->s[0], 0 , nn * sizeof(poly)); // remove when checks are working?
    for(i = 1; i < owt->r; i++)
        owt->s[i] = &owt->s[i-1][owt->n[i-1]];
}

void lnp_statement_init(statement ost, const statement ist, const lnp_params pp) {
    size_t i, r, maxr;

    r = 5 * 2;  // z1s: s1,s2,Z1LO,s4,s5 (s3+s6+z2 merged)
    r += 2 * 2; // z1v: masked vi
    r += 1; // xbin: tshat,tvhat,v0hat,hhat,wshat,wvhat,uhat,vhat

    maxr = r;
    maxr += 1; // sigmam1(xbin)

    assert (r == NWIT);
    assert (maxr == NWIT + 1);

    statement_init(ost, r, maxr);

    // use output lengths from pp->len[]
    for (i = 0; i < NWIT; i++)
        ost->n[i] = pp->len[i];

    ost->n[XBIN] = pp->xbinlen;
    // pre-allocate space for sigmam1(xbin)
    ost->n[XBIN + 1] = ost->n[XBIN];

    for (i = Z1S10; i <= Z1V21; i++)
        ost->normty[i] = L2APPROX;
    ost->normty[XBIN] = BIN;

    // norm bounds: uniform parts
    ost->normsq[Z1S10] = pp->z1s0betasq[0];
    ost->normsq[Z1S20] = pp->z1s0betasq[1];
    ost->normsq[Z1LO]  = pp->z1s0betasq[2]; // merged s3+s6+z2
    ost->normsq[Z1S40] = pp->z1s0betasq[3];
    ost->normsq[Z1S50] = pp->z1s0betasq[4];
    ost->normsq[Z1V10] = pp->z1v0betasq;
    ost->normsq[Z1V20] = pp->z1v0betasq;
    // norm bounds: gaussian parts
    ost->normsq[Z1S11] = pp->z1s1betasq[0];
    ost->normsq[Z1S21] = pp->z1s1betasq[1];
    ost->normsq[Z1HI]  = pp->z1s1betasq[2]; // merged s3+s6+z2
    ost->normsq[Z1S41] = pp->z1s1betasq[3];
    ost->normsq[Z1S51] = pp->z1s1betasq[4];
    ost->normsq[Z1V11] = pp->z1v1betasq;
    ost->normsq[Z1V21] = pp->z1v1betasq;

    ost->normsq[XBIN] = N * ost->n[XBIN]; // trivial l2-bound for binary

    memcpy (ost->h, ist->h, HASHLEN);
}

void lnp_proof_init(lnp_proof pi, const lnp_params pp) {
    // outer commitments: U1,U2,z,U4,U5
    pi->m[0] = _aligned_alloc(64, (4 * pp->kappa_linfmsis + 256 / N) * sizeof(polz));
    pi->m[1] = &pi->m[0][pp->kappa_linfmsis];
    pi->m[2] = &pi->m[0][2 * pp->kappa_linfmsis];
    pi->m[3] = &pi->m[0][2 * pp->kappa_linfmsis + 256 / N];
    pi->m[4] = &pi->m[0][3 * pp->kappa_linfmsis + 256 / N];
}

void lnp_proof_free(lnp_proof pi) {
    free (pi->m[0]);
}

static void lnp_addcheck_commmit (comcnst c[4], const lnp_params pp, const lnp_proof pi) {
    lnp_addcheck_commmit_in_clear (c[0], pi->m[0], pp->kappa_linfmsis, pp->off[TSHAT], pp->len[TSHAT]);
    lnp_addcheck_commmit_in_clear (c[1], pi->m[1], pp->kappa_linfmsis, pp->off[TVHAT], pp->len[TVHAT] + pp->len[V0HAT]);
    lnp_addcheck_commmit_in_clear (c[2], pi->m[3], pp->kappa_linfmsis, pp->off[HHAT], pp->len[HHAT]);
    lnp_addcheck_commmit_in_clear (c[3], pi->m[4], pp->kappa_linfmsis, pp->off[WSHAT], pp->len[WSHAT] + pp->len[WVHAT] + pp->len[UHAT] + pp->len[VHAT]);
}

static void lnp_addcheck_commmit_in_clear (comcnst c, const polz *capu, size_t rank, 
                               size_t off, size_t len) {
  comcnst_init(c, rank, 1, 0, 0);

  c->comk_off[0] = 0;
  c->comw_off[0] = off;
  c->comw_len[0] = len;
  polzvec_topolxvec(c->b, capu, 0, 1, rank);
}

static void lnp_addcheck_lift_zero_coeff(sparsecnst c[LIFTS], size_t off) {
  polxvec powers;
  int i;

  polxvec_init(powers, LOGQ, 1);
  polxvec_powers(powers, 2, -1, 1);

  for(i = 0; i < LIFTS; i++) {
    sparsecnst_init(c[i], 1);
    linfunc_init(c[i]->lin, 1, 1, 1);

    c[i]->lin->off[0] = off;
    polxvec_init(c[i]->lin->phi[0], LOGQ, 1);
    polxvec_copy(c[i]->lin->phi[0], powers);

    off += LOGQ;
  }

  polxvec_free(powers);
}

// s-opening and v-opening share the same verifier equation
//   A*zi + (-G2)*wihat + c*(-G2)*tihat = 0   (for i in {s, v})
// derived from
//   A*(y + c*w) + A2*(y2 + c*r) - A*y - A2*y2 - c*(A*w + A2*r) = 0.
// They differ in the layout of zi:
//  - s-opening has z1s scattered across Z1S10..Z1S50 / Z1LO because A1 is
//    split as A1_s123 | A1_s45 | A1_s6 (each extension-ring-aligned); z2s (= rs)
//    sits inside Z1LO after s3+s6.
//  - v-opening has z1v contiguous at Z1V10..Z1V20 against a single A1v; z2v
//    (= rv) sits inside Z1LO after s3+s6+z2s.
//
// s-opening: split A1 opening
static void lnp_addcheck_sopening(comcnst cnst, const lnp_params pp, polx chalx) {
  size_t z2s_out_0, z2s_out_1;
  size_t s123_len, s45_len;
  size_t s123_ckoff, s45_ckoff, s6_ckoff;
  uint64_t deg;
  polxvec powers;

  z2s_out_0 = pp->off[Z1LO] + pp->silen[2] + pp->silen[5];
  z2s_out_1 = pp->off[Z1HI] + pp->silen[2] + pp->silen[5];
  s123_len = pp->silen[0] + pp->silen[1] + pp->silen[2];
  s45_len = pp->silen[3] + pp->silen[4];
  deg = next2power(pp->kappa_l2msis1);
  s123_ckoff = 0;
  s45_ckoff = extlen(s123_len, deg);
  s6_ckoff = s45_ckoff + extlen(s45_len, deg);

  polxvec_init(powers, LOGQ, 1);
  polxvec_powers(powers, 2, -1, 1); // -G2

  comcnst_init(cnst, pp->kappa_l2msis1, 8, 2, 2);

  // uniform z1s: A1_s123*(s1||s2||s3)
  cnst->scalar[0] = 1;
  cnst->comk_off[0] = s123_ckoff;
  cnst->comw_off[0] = pp->off[Z1S10];
  cnst->comw_len[0] = s123_len;
  // uniform z1s: A1_s45*(s4||s5)
  cnst->scalar[1] = 1;
  cnst->comk_off[1] = s45_ckoff;
  cnst->comw_off[1] = pp->off[Z1S40];
  cnst->comw_len[1] = s45_len;
  // uniform z1s: A1_s6*s6
  cnst->scalar[2] = 1;
  cnst->comk_off[2] = s6_ckoff;
  cnst->comw_off[2] = pp->off[Z1LO] + pp->silen[2];
  cnst->comw_len[2] = pp->silen[5];
  // uniform z2s: A2*z2s
  cnst->scalar[3] = 1;
  cnst->comk_off[3] = pp->a2soff;
  cnst->comw_off[3] = z2s_out_0;
  cnst->comw_len[3] = pp->rslen;

  // gaussian z1s: b1*A1_s123*(s1||s2||s3)
  cnst->scalar[4] = 1LL << pp->b1;
  cnst->comk_off[4] = s123_ckoff;
  cnst->comw_off[4] = pp->off[Z1S11];
  cnst->comw_len[4] = s123_len;
  // gaussian z1s: b1*A1_s45*(s4||s5)
  cnst->scalar[5] = 1LL << pp->b1;
  cnst->comk_off[5] = s45_ckoff;
  cnst->comw_off[5] = pp->off[Z1S41];
  cnst->comw_len[5] = s45_len;
  // gaussian z1s: b1*A1_s6*s6
  cnst->scalar[6] = 1LL << pp->b1;
  cnst->comk_off[6] = s6_ckoff;
  cnst->comw_off[6] = pp->off[Z1HI] + pp->silen[2];
  cnst->comw_len[6] = pp->silen[5];
  // gaussian z2s: b2*A2*z2s
  cnst->scalar[7] = 1LL << pp->b2;
  cnst->comk_off[7] = pp->a2soff;
  cnst->comw_off[7] = z2s_out_1;
  cnst->comw_len[7] = pp->rslen;

  // (-G2)*wshat
  cnst->phiw_off[0] = pp->off[WSHAT];
  polxvec_init(cnst->phi[0], LOGQ, 1);
  polxvec_copy(cnst->phi[0], powers);

  // c*(-G2)*tshat
  cnst->phiw_off[1] = pp->off[TSHAT];
  polxvec_init(cnst->phi[1], LOGQ, 1);
  polxvec_polx_mul(cnst->phi[1], chalx, powers);
  polxvec_refresh(cnst->phi[1]);

  // = 0
  polxvec_setzero(cnst->b, 0, 1, cnst->b->len);

  polxvec_free(powers);
}

// v-opening: contiguous A1 opening
static void lnp_addcheck_vopening(comcnst cnst, const lnp_params pp, polx chalx) {
  size_t z2v_out_0, z2v_out_1;
  polxvec powers;

  z2v_out_0 = pp->off[Z1LO] + pp->silen[2] + pp->silen[5] + pp->rslen;
  z2v_out_1 = pp->off[Z1HI] + pp->silen[2] + pp->silen[5] + pp->rslen;

  polxvec_init(powers, LOGQ, 1);
  polxvec_powers(powers, 2, -1, 1); // -G2

  comcnst_init(cnst, pp->kappa_l2msis2, 4, 2, 2);

  // A1v*z1v = A1v*(z1v_1*b1 + z1v_0) = b1*A1v*z1v_1 + A1v*z1v_0
  cnst->scalar[0] = 1;
  cnst->comk_off[0] = 0;
  cnst->comw_off[0] = pp->off[Z1V10];
  cnst->comw_len[0] = pp->vtildelen;
  cnst->scalar[1] = 1LL << pp->b1;
  cnst->comk_off[1] = 0;
  cnst->comw_off[1] = pp->off[Z1V11];
  cnst->comw_len[1] = pp->vtildelen;

  // A2v*z2v = A2v*(z2v_1*b2 + z2v_0) = b2*A2v*z2v_1 + A2v*z2v_0
  cnst->scalar[2] = 1;
  cnst->comk_off[2] = pp->a2voff;
  cnst->comw_off[2] = z2v_out_0;
  cnst->comw_len[2] = pp->rvlen;
  cnst->scalar[3] = 1LL << pp->b2;
  cnst->comk_off[3] = pp->a2voff;
  cnst->comw_off[3] = z2v_out_1;
  cnst->comw_len[3] = pp->rvlen;

  // (-G2)*wvhat
  cnst->phiw_off[0] = pp->off[WVHAT];
  polxvec_init(cnst->phi[0], LOGQ, 1);
  polxvec_copy(cnst->phi[0], powers);

  // c*(-G2)*tvhat
  cnst->phiw_off[1] = pp->off[TVHAT];
  polxvec_init(cnst->phi[1], LOGQ, 1);
  polxvec_polx_mul(cnst->phi[1], chalx, powers);
  polxvec_refresh(cnst->phi[1]);

  // = 0
  polxvec_setzero(cnst->b, 0, 1, cnst->b->len);

  polxvec_free(powers);
}

static void lnp_aggregate_zq (
  sparsecnst *zqagg,
  const lnp_params pp,
  const statement ist,
  const uint8_t *jlmat1,
  const uint8_t *jlmat2,
  const uint8_t *jlmat3,
  const uint8_t *jlmat4,
  const polz *zp,
  uint8_t h[HASHLEN]
) {
  zqcnstset lnpzq;
  size_t i, j, nchalz, nchalx, v0off, umoff, ybits, si_pos_merged;
  int64_t *chalz, *chalz1, *chalz2;
  polxvec chalx, phi, chalx1, chalx2, phip, phiy, phiu, sv, phiv0;
  polxvec monesxvec, zpx, cx, phit, phiw, b;
  poly one, mones;
  polx onex;
  int64_t *chalz_jl[1 + LNP_NPROJ];
  polxvec phip_jl[1 + LNP_NPROJ];
  quil_jl_mat_job jl_jobs[1 + LNP_NPROJ];

  // sparse:
  // - 1 binary
  // - 1 agg projection of (w,t)
  // - LNP_NPROJ agg projections of si (s1..s4, not s5=sigmam1(s4))
  // sigmam1:
  // - sigmam1(w-t)
  zqcnstset_init (lnpzq, 2 + LNP_NPROJ, 2 + LNP_NPROJ, 1, 1, 0);
  polxvec_init (monesxvec, 1, 1);

  // init constants

  memset(one, 0, sizeof(one));
  one->c[0] = 1;
  polx_frompoly(onex, one, 1);

  for (i = 0; i < N; i++)
    mones->c[i] = -1;
  polxvec_frompolyvec(monesxvec, &mones, 1, 1, 1);

#if 1
  // sigmam1 cnst on v1=w-t

  sigmam1cnst_init (lnpzq->sigmam1[0], pp->off[Z1V10], pp->off[Z1V20], pp->vtildelen / 2, 0);
  lnpzq->sigmam1_nchal += pp->vtildelen / 2;
#endif
#if 1
  // binary cnst on v1=w-t
  sparsecnst_init (lnpzq->sparse[0], 1);
  lnpzq->sparse_nchal += 1;

  quadfunc_init (lnpzq->sparse[0]->quad, 1, 1);
  lnpzq->sparse[0]->quad->rows[0] = Z1V10; // index of (w,t) in array
  lnpzq->sparse[0]->quad->cols[0] = Z1V20; // index of sigmam1(w,t) in array
  polx_copy(lnpzq->sparse[0]->quad->coeffs[0], onex);

  linfunc_init (lnpzq->sparse[0]->lin, 1, 1, 1);
  lnpzq->sparse[0]->lin->off[0] = pp->off[Z1V20]; // position of sigmam1(w,t) = v20 slot
  polxvec_init (lnpzq->sparse[0]->lin->phi[0], pp->vtildelen / 2, 1);
  for (j = 0; j < pp->vtildelen / 2; j++){
    polxvec_init_subvec2 (phi, lnpzq->sparse[0]->lin->phi[0], 
                           j, 1, 1);
    polxvec_copy (phi, monesxvec);
  }
#endif
  // Sample every projection challenge in the original transcript order (the
  // (w,t) projection, then the LNP_NPROJ s_i projections; nothing else touches
  // h in between), then collapse the shared matrices concurrently. Each
  // collapse writes its own output with the unmodified serial kernel.
  for (j = 0; j < 1 + LNP_NPROJ; j++) {
    chalz_jl[j] = _malloc(256 * sizeof(int64_t));
    sample_chalz (chalz_jl[j], 256, h);
    polxvec_init (phip_jl[j], j == 0 ? pp->vtildelen / 2 : pp->silen_max, 1);
    jl_jobs[j] = (quil_jl_mat_job){.out=phip_jl[j],
                                   .jlmat1=j == 0 ? jlmat3 : jlmat1,
                                   .jlmat2=j == 0 ? jlmat4 : jlmat2,
                                   .chalz=chalz_jl[j]};
  }
  quil_resource_trace("lnp_jl_collapse_begin");
  quil_jl_mat_execute_all (jl_jobs, 1 + LNP_NPROJ);
  quil_resource_trace("lnp_jl_collapse_end");

#if 1
  // projection of (w,t): c*Pi*(w,t) + c*y = z
  // y needs to be recomposed from binary yhat
  chalz = chalz_jl[0];

  polxvec_init_subvec2 (phip, phip_jl[0], 0, 1, pp->vtildelen / 2); // linear part corresponding to (w,t)
  ybits = pp->logsdp + YHAT_EXTRA_BITS;
  polxvec_init (phiy, ybits, 1);
  polxvec_init (zpx, 256 / N, 1);
  polxvec_init (cx, 256 / N, 1);
  polxvec_init (b, 256 / N, 1);

  jl_aggregate_proj (phiy, ybits, chalz); // linear part corresponding to yhat (part of s6)
  polxvec_init_subvec2 (sv, phiy, ybits - 1, 1, 1); // negate part corresponding to most significant bit (required after jl_aggregate_proj)
  polxvec_neg (sv, sv);
  polxvec_neg (phiy, phiy); // because jl_aggregate_proj does -sigmam1()
  
  polzvec_topolxvec (zpx, zp, 0, 1, 256 / N);
  polxvec_fromint64vec2 (cx, chalz, 256 / N, 1, 1); // does this work for N < 256?
  polxvec_sigmam1 (cx, cx);
  polxvec_sprod (b, cx, zpx);

  sparsecnst_init (lnpzq->sparse[1], 1);
  lnpzq->sparse_nchal += 1;

  linfunc_init (lnpzq->sparse[1]->lin, 1, 2, 2);

  polxvec_init (lnpzq->sparse[1]->lin->phi[0], ybits, 1);
  lnpzq->sparse[1]->lin->off[0] = pp->off[Z1LO] + pp->silen[2] + LIFTS * LOGQ; // s6 position + len(ghat)
  polxvec_copy (lnpzq->sparse[1]->lin->phi[0], phiy);

  polxvec_init (lnpzq->sparse[1]->lin->phi[1], pp->vtildelen / 2, 1);
  lnpzq->sparse[1]->lin->off[1] = pp->off[Z1V10];
  polxvec_copy (lnpzq->sparse[1]->lin->phi[1], phip);

  polxvec_copy (lnpzq->sparse[1]->b, b);

  sparsecnst_refresh (lnpzq->sparse[1]);

  polxvec_free (b);
  polxvec_free (zpx);
  polxvec_free (cx);
  polxvec_free (phip_jl[0]);
  polxvec_free (phiy);
  free (chalz_jl[0]);
#endif
#if 1
  // projection of si: c*Pi*si + c*ui = c*2^ki*wi - c*2^ki*ti + c*v0i
  // ui,v0i need to be recomposed from binary yhat

  polxvec_init (phit, 256 / N, 1);
  polxvec_init (phiw, 256 / N, 1);

  v0off = 0;
  umoff = 0;
  for (i = 0; i < LNP_NPROJ; i++) {

  chalz = chalz_jl[1 + i];
  polxvec_init_subvec2 (phip, phip_jl[1 + i], 0, 1, pp->silen_max); // linear part corresponding to si

  polxvec_init (phiv0, pp->k[i], 1);
  jl_aggregate_proj (phiv0, pp->k[i], chalz); // linear part corresponding to v0ihat (part of xbin)
  polxvec_init_subvec2 (sv, phiv0, pp->k[i] - 1, 1, 1); // negate part corresponding to most significant bit (required after jl_aggregate_proj)
  polxvec_neg (sv, sv);

  polxvec_init (phiu, pp->k[i], 1);
  polxvec_copy (phiu, phiv0); // linear part corresponding to ui (part of s6)
  polxvec_neg (phiu, phiu); // because jl_aggregate_proj does -sigmam1()

  polxvec_fromint64vec2 (phit, chalz, 256 / N, 1, 1);
  polxvec_refresh (phit);
  polxvec_sigmam1 (phit, phit); // linear part corresponding to ti
  polxvec_scale (phit, phit, (int64_t)1 << pp->k[i]);
  polxvec_refresh (phit);
  polxvec_neg (phiw, phit); // linear part corresponding to wi

  sparsecnst_init (lnpzq->sparse[2 + i], 1);
  lnpzq->sparse_nchal += 1;

  linfunc_init (lnpzq->sparse[2 + i]->lin, 1, 5, 5);

  polxvec_init (lnpzq->sparse[2 + i]->lin->phi[0], pp->k[i], 1);
  lnpzq->sparse[2 + i]->lin->off[0] = pp->off[Z1LO] + pp->silen[2] + LIFTS * LOGQ + (pp->logsdp + YHAT_EXTRA_BITS) * 256 / N + umoff; // s6 position + len(ghat,yhat,umask[0..i-1])
  polxvec_copy (lnpzq->sparse[2 + i]->lin->phi[0], phiu);

  polxvec_init (lnpzq->sparse[2 + i]->lin->phi[1], pp->silen[i], 1);
  // Position of s_i (i=0..3) in merged sxl: Z1S10/Z1S20 for i=0,1; Z1LO for i=2
  // (s3 is at the start of Z1LO); Z1S40 for i=3 (s4).
  if (i == 0)      si_pos_merged = pp->off[Z1S10];
  else if (i == 1) si_pos_merged = pp->off[Z1S20];
  else if (i == 2) si_pos_merged = pp->off[Z1LO];
  else             si_pos_merged = pp->off[Z1S40]; // i == 3
  lnpzq->sparse[2 + i]->lin->off[1] = si_pos_merged;
  polxvec_init_subvec2 (sv, phip, 0, 1, pp->silen[i]);
  polxvec_copy (lnpzq->sparse[2 + i]->lin->phi[1], sv);

  polxvec_init (lnpzq->sparse[2 + i]->lin->phi[2], pp->k[i], 1);
  lnpzq->sparse[2 + i]->lin->off[2] = pp->off[V0HAT] + v0off;
  polxvec_copy (lnpzq->sparse[2 + i]->lin->phi[2], phiv0);

  polxvec_init (lnpzq->sparse[2 + i]->lin->phi[3], 256 / N, 1);
  lnpzq->sparse[2 + i]->lin->off[3] = pp->off[Z1V10] + pp->vtildelen / 4 + i; // t[i] within v10
  polxvec_copy (lnpzq->sparse[2 + i]->lin->phi[3], phit);

  polxvec_init (lnpzq->sparse[2 + i]->lin->phi[4], 256 / N, 1);
  lnpzq->sparse[2 + i]->lin->off[4] = pp->off[Z1V10] + i; // w[i] within v10
  polxvec_copy (lnpzq->sparse[2 + i]->lin->phi[4], phiw);

  sparsecnst_refresh (lnpzq->sparse[2 + i]);

  v0off += pp->v0ihatlen[i];
  umoff += pp->k[i] * 256 / N;
  polxvec_free (phiu);
  polxvec_free (phiv0);
  polxvec_free (phip_jl[1 + i]);
  free (chalz_jl[1 + i]);
  }

  polxvec_free (phiw);
  polxvec_free (phit);
#endif

  // aggregate

  nchalz = ist->zqcnst->sparse_nchal + lnpzq->sparse_nchal;
  chalz = _malloc(nchalz * sizeof(int64_t));
  chalz1 = chalz;
  chalz2 = chalz + ist->zqcnst->sparse_nchal;

  nchalx = ist->zqcnst->sigmam1_nchal + lnpzq->sigmam1_nchal;
  polxvec_init(chalx, nchalx, 1);
  polxvec_init_subvec2 (chalx1, chalx, 0, 1, ist->zqcnst->sigmam1_nchal );
  polxvec_init_subvec2 (chalx2, chalx, ist->zqcnst->sigmam1_nchal, 1, lnpzq->sigmam1_nchal);

  for (i = 0; i < LIFTS; i++) {
    sample_chalz (chalz, nchalz, h);
    sample_chalx_uniform (chalx, h);

    sparsecnst_init(zqagg[i], 1);
    // alloc upper bound on ncoeffs
    quadfunc_init(zqagg[i]->quad, 0, (8 * 8 + 8) / 2);
    linfunc_init(zqagg[i]->lin, 1, 1, 1);

    zqagg[i]->lin->off[0] = 0;
    polxvec_init(zqagg[i]->lin->phi[0], pp->wtlen, 1);
    polxvec_setzero(zqagg[i]->lin->phi[0], 0, 1, pp->wtlen);

    // aggregate labrador eqs
    zqcnstset_aggregate_add(zqagg[i], ist->zqcnst, chalz1, chalx1);
    // aggregate lnp eqs
    zqcnstset_aggregate_add(zqagg[i], lnpzq, chalz2, chalx2);

    // free unused coeffs
    zqagg[i]->quad->coeffs = realloc(zqagg[i]->quad->coeffs, 
                                     zqagg[i]->quad->len*sizeof(polx));
  }

  free(chalz);
  polxvec_free(chalx);
  zqcnstset_free (lnpzq);
  polxvec_free (monesxvec);
}

// decompose masked projection Pi*s[i] + umask[i] as 2^k*v1 + v0
// s.t. v0 is unifrom mod 2^k and v1 is ternary.
// v1 = w - t
#define DEBUG__decomp_projection 0
static int __reject_decomp_proj (poly *w, poly *t, polz *v0, const polz *maskedproj, size_t len, size_t k)
{
    size_t i, j, ncarries;
    zz coeffzz;
    int64_t coeff, v0coeff, v1coeff, wcoeff, tcoeff;
    int reject;
    const int64_t twopowk = ((int64_t)1 << k);
    const int64_t ub = ((int64_t)1 << (k-1)) - 1;
    const int64_t lb = -((int64_t)1 << (k-1));

    reject = 1;
    ncarries = 0;
    for (i = 0; i < len; i++) {
        for (j = 0; j < N; j++) {
            polz_getcoeff (coeffzz, maskedproj[i], j);
            coeff = int64_fromzz (coeffzz);

            v0coeff = coeff % twopowk;
            if (v0coeff > ub)
                v0coeff -= twopowk;
            else if (v0coeff < lb)
                v0coeff += twopowk;

            v1coeff = (coeff - v0coeff) / twopowk;

            if (v1coeff == 0) {
                wcoeff = 0;
                tcoeff = 0;
            } else if (v1coeff == 1) {
                wcoeff = 1;
                tcoeff = 0;
                ncarries++;
            } else if (v1coeff == -1) {
                wcoeff = 0;
                tcoeff = 1;
                ncarries++;
            } else {
                printf("ERROR: cannot decompose Pi*s[%lu] + umask[%lu] as 2^k*v1 + v0 s.t. v0 is unifrom mod 2^k and v1 is ternary.\n",i,i);
                exit (1);
            }

#if DEBUG__decomp_projection
            if (twopowk*(wcoeff-tcoeff)+v0coeff != coeff)
                printf("ERROR\n");
            if (v1coeff > 1)
                printf("ERROR > 1\n");
            if (v1coeff < -1)
                printf("ERROR < -1\n");
#endif

            polz_setcoeff_fromint64 (v0[i], v0coeff, j);
            w[i]->c[j] = wcoeff;
            t[i]->c[j] = tcoeff;
        }
    }

    if (ncarries <= LNP_MAXCARRIES)
        reject = 0;
    return reject;
}

static void lnp_aggregate_rq(
  sparsecnst finalcnst,
  const lnp_params pp,
  const statement ist,
  const sparsecnst zqagg[LIFTS],
  uint8_t h[HASHLEN]
)
{
  size_t nchalx;
  polxvec chalx, chalx_sv;

  nchalx = ist->rqcnst->sparse_nchal + ist->rqcnst->com_nchal;
  polxvec_init (chalx, nchalx + LIFTS, 1);
  sample_chalx_aggregate (chalx, h);

  sparsecnst_init (finalcnst, 1);
  quadfunc_init (finalcnst->quad, 0, 5 * 4);
  linfunc_init (finalcnst->lin, 1, 1, 1);

  finalcnst->lin->off[0] = 0;
  polxvec_init (finalcnst->lin->phi[0], pp->wtlen, 1);
  polxvec_setzero (finalcnst->lin->phi[0], 0, 1, pp->wtlen);

  polxvec_init_subvec2 (chalx_sv, chalx, 0, 1, nchalx);
  rqcnstset_aggregate_add (finalcnst, ist->rqcnst, chalx_sv);

  polxvec_init_subvec2 (chalx_sv, chalx, nchalx, 1, LIFTS);
  sparsecnst_aggregate_add (finalcnst, zqagg, LIFTS, chalx_sv, NULL, 1);

  quil_sparsecnst_parallel_refresh (finalcnst);

  polxvec_free (chalx);
}

void lnp_params_print(lnp_params pp) {
  size_t i;

  printf("Params:\n");

  printf("  s[i] lengths          : ");
  for (i = 0; i < 5 + 1; i++)
    printf("%lu%s", pp->silen[i], i < 5 + 1 - 1 ? "," : "\n");
  printf("  beta[i] norm bounds   : ");
  for (i = 0; i < 5 + 1; i++)
    printf("%0.2Lf%s", pp->sibeta[i], i < 5 + 1 - 1 ? "," : "\n");
  printf("  log(beta[i])          : ");
  for (i = 0; i < 5 + 1; i++)
    printf("%.0Lf%s", ceill(log2l(pp->sibeta[i])), i < 5 + 1 - 1 ? "," : "\n");

  printf("  k[i]                  : ");
  for (i = 0; i < LNP_NPROJ; i++)
    printf("%lu%s", pp->k[i], i < LNP_NPROJ - 1 ? "," : "\n");

  printf("  MSIS linf rank        : %lu\n", pp->kappa_linfmsis);
  printf("  MSIS l2 1 rank        : %lu\n", pp->kappa_l2msis1);
  printf("  MSIS l2 2 rank        : %lu\n", pp->kappa_l2msis2);
  printf("  A1soff,A2soff         : 0,%lu\n", pp->a2soff);
  printf("  A1voff,A2voff         : 0,%lu\n", pp->a2voff);
    
  printf("  sdp                   : ");
  printf("%.2Lf\n", (long double)1.55 * (1 << pp->logsdp));
  printf("  log(14*stdp)          : ");
  printf("%.0Lf\n", ceill(log2l(14 * (long double)1.55 * (1 << pp->logsdp))));
  printf("  gammap                : ");
  printf("%.2Lf\n", pp->gammap);
  printf("  Mp                    : ");
  printf("%.2Lf\n", pp->capmp);

  printf("  sd1                   : ");
  printf("%.2Lf\n", (long double)1.55 * (1 << pp->logsd1));
  printf("  log(14*std1)          : ");
  printf("%.0Lf\n", ceill(log2l(14 * (long double)1.55 * (1 << pp->logsd1))));
  printf("  gamma1                : ");
  printf("%.2Lf\n", pp->gamma1);
  printf("  M1                    : ");
  printf("%.2Lf\n", pp->capm1);
  printf("  b1                    : %lu\n", pp->b1);

  printf("  sd2                   : ");
  printf("%.2Lf\n", (long double)1.55 * (1 << pp->logsd2));
  printf("  log(14*std2)          : ");
  printf("%.0Lf\n", ceill(log2l(14 * (long double)1.55 * (1 << pp->logsd2))));
  printf("  gamma2                : ");
  printf("%.2Lf\n", pp->gamma2);
  printf("  M2                    : ");
  printf("%.2Lf\n", pp->capm2);
  printf("  b2                    : %lu\n", pp->b2);
}
