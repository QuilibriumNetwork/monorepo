#include "rejection.h"
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>

// assume in the following that long double can represent 64 bit integers

static inline uint64_t _bytes2uint63(uint8_t bytes[8])
{
    uint64_t ret = 0;

    ret |= (uint64_t)bytes[0] | ((uint64_t)bytes[1] << 8)
        | ((uint64_t)bytes[2] << 16) | ((uint64_t)bytes[3] << 24)
        | ((uint64_t)bytes[4] << 32) | ((uint64_t)bytes[5] << 40)
        | ((uint64_t)bytes[6] << 48) | ((uint64_t)(bytes[7] & 0x7f) << 56);
    return ret;
}

// return random long double in [0,1)
static inline long double _ldrand(quil_prg_stream *state) {
    const uint64_t denom = (uint64_t)1 << 63;
    uint64_t nom;
    uint8_t buf[QUIL_PRG_BLOCKBYTES];
    long double ret;

    quil_prg_squeeze(buf, 1, state);
    nom = _bytes2uint63(buf);
    ret = (long double)nom / denom;
    quil_prg_clear(buf,sizeof(buf));
    return ret;
}

// standard rejection sampling
// zv  : <z,v>
// vv  : <v,v>
// var : variance
// m   : repetition rate M
int quil_is_rejected_std0_stream(quil_prg_stream *state, int64_t zv, int64_t vv,
                        long double var, long double m) {
    if(vv < 0 || !isfinite(var) || var <= 0 || !isfinite(m) || m < 1)return -1;
    /* Widen before integer arithmetic: valid int64 inputs need up to 66 bits
     * for vv - 2*zv. Floating conversion happens only after the exact sum. */
    const __int128 numerator = (__int128)vv - 2 * (__int128)zv;
    const long double u = _ldrand(state);
    const int rejected = u * m > expl((long double)numerator / (2 * var));

    return rejected;
}

// standard rejection sampling
// zv  : <z,v>
// vv  : <v,v>
// var : variance
// m   : repetition rate M
int quil_is_rejected_sgnleak0_stream(quil_prg_stream *state, int64_t zv, int64_t vv,
                          long double var, long double m) {
    int rejected = 1;
    if(vv < 0 || !isfinite(var) || var <= 0 || !isfinite(m) || m < 1)return -1;

    if (zv < 0)
        goto ret;

    rejected = quil_is_rejected_std0_stream(state, zv, vv, var, m);
ret:
    return rejected;
}

// bimodal rejection sampling
// zv  : <z,v>
// vv  : <v,v>
// var : variance
// m   : repetition rate M
int quil_is_rejected_bimodal0_stream(quil_prg_stream *state, int64_t zv, int64_t vv,
                            long double var, long double m)
{
    long double u;
    int rejected;

    if(vv < 0 || !isfinite(var) || var <= 0 || !isfinite(m) || m < 1)return -1;
    u = _ldrand(state);
    long double comparison = u * m * expl(-(long double)vv / (2 * var)) * coshl(zv / var);
    if(isnan(comparison))return -1;
    if (comparison > 1)
        rejected = 1;
    else
        rejected = 0;

    return rejected;
}

// standard rejection sampling
// var : variance
// m   : repetition rate M
int quil_is_rejected_std1_stream(quil_prg_stream *state, poly *z, poly *v, size_t len,
                        long double var, long double m) {
    int64_t zv, vv;

    zv = polyvec_sprodz(z, v, 1, 1, len);
    vv = polyvec_sprodz(v, v, 1, 1, len);
    return quil_is_rejected_std0_stream(state, zv, vv, var, m);
}

// binomial rejection sampling
// var : variance
// m   : repetition rate M
int quil_is_rejected_bimodal1_stream(quil_prg_stream *state, poly *z, poly *v, size_t len,
                            long double var, long double m) {
    int64_t zv, vv;

    zv = polyvec_sprodz(z, v, 1, 1, len);
    vv = polyvec_sprodz(v, v, 1, 1, len);
    return quil_is_rejected_bimodal0_stream(state, zv, vv, var, m);
}
int is_rejected_std0(aes128ctr_ctx *state,int64_t zv,int64_t vv,long double var,long double m) {
  quil_prg_stream stream={state,quil_prg_aes128_squeeze};
  return quil_is_rejected_std0_stream(&stream,zv,vv,var,m);
}

int is_rejected_sgnleak0(aes128ctr_ctx *state,int64_t zv,int64_t vv,long double var,long double m) {
  quil_prg_stream stream={state,quil_prg_aes128_squeeze};
  return quil_is_rejected_sgnleak0_stream(&stream,zv,vv,var,m);
}

int is_rejected_bimodal0(aes128ctr_ctx *state,int64_t zv,int64_t vv,long double var,long double m) {
  quil_prg_stream stream={state,quil_prg_aes128_squeeze};
  return quil_is_rejected_bimodal0_stream(&stream,zv,vv,var,m);
}

int is_rejected_std1(aes128ctr_ctx *state,poly *z,poly *v,size_t len,long double var,long double m) {
  quil_prg_stream stream={state,quil_prg_aes128_squeeze};
  return quil_is_rejected_std1_stream(&stream,z,v,len,var,m);
}

int is_rejected_bimodal1(aes128ctr_ctx *state,poly *z,poly *v,size_t len,long double var,long double m) {
  quil_prg_stream stream={state,quil_prg_aes128_squeeze};
  return quil_is_rejected_bimodal1_stream(&stream,z,v,len,var,m);
}

static quil_rejection_decider quil_private_decider = NULL;
void quil_set_rejection_decider(quil_rejection_decider decider) {
  quil_private_decider=decider;
}
int quil_rejection_decide_sd_256_stream(quil_prg_stream *state,unsigned int kind,int64_t zv,int64_t vv,long double standard_deviation,long double repetition) {
  uint8_t standard_deviation_parts[16],repetition_parts[16];
  int32_t standard_deviation_exponent,repetition_exponent;
  if(!quil_private_decider || kind>2 || vv<0 || repetition<1
     || quil_rejection_binary_parts(standard_deviation,standard_deviation_parts,&standard_deviation_exponent)
     || quil_rejection_binary_parts(repetition,repetition_parts,&repetition_exponent))return -1;
  if(kind==1 && zv<0)return 1;
  uint8_t bytes[QUIL_PRG_BLOCKBYTES];
  quil_prg_squeeze(bytes,1,state);
  int result=quil_private_decider(kind,zv,vv,bytes,standard_deviation_parts,standard_deviation_exponent,repetition_parts,repetition_exponent);
  quil_prg_clear(bytes,sizeof(bytes));
  return result==0 || result==1 ? result : -1;
}
