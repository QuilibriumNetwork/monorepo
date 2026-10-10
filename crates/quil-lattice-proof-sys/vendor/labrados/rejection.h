#ifndef REJECTION_H
#define REJECTION_H
#include "aesctr.h"
#include "prg_stream.h"
#include "rejection_params.h"
#include "poly.h"

/* Caller holds the process-wide native-state lock for registration and use.
 * The callback receives exact public parameters and a private 256-bit draw.
 * NULL disables private proof sampling; there is no floating-point fallback. */
typedef int (*quil_rejection_decider)(unsigned int,int64_t,int64_t,const uint8_t *,const uint8_t *,int32_t,const uint8_t *,int32_t);
void quil_set_rejection_decider(quil_rejection_decider decider);
int quil_rejection_decide_sd_256_stream(quil_prg_stream *state,unsigned int kind,int64_t zv,int64_t vv,long double standard_deviation,long double repetition);

/* Return 0=accept, 1=retry, -1=invalid parameters/numerical error.
 * A negative result must abort proving, never become a sampling retry. */
int is_rejected_std0(aes128ctr_ctx *state, int64_t zv, int64_t vv,
                        long double var, long double m);
int is_rejected_std1(aes128ctr_ctx *state, poly *z, poly *v, size_t len,
                        long double var, long double m);

int is_rejected_sgnleak0(aes128ctr_ctx *state, int64_t zv, int64_t vv,
                            long double var, long double m);

int is_rejected_bimodal0(aes128ctr_ctx *state, int64_t zv, int64_t vv,
                            long double var, long double m);
int is_rejected_bimodal1(aes128ctr_ctx *state, poly *z, poly *v, size_t len,
                            long double var, long double m);

int quil_is_rejected_std0_stream(quil_prg_stream *state,int64_t zv,int64_t vv,long double var,long double m);
int quil_is_rejected_sgnleak0_stream(quil_prg_stream *state,int64_t zv,int64_t vv,long double var,long double m);
int quil_is_rejected_bimodal0_stream(quil_prg_stream *state,int64_t zv,int64_t vv,long double var,long double m);
int quil_is_rejected_std1_stream(quil_prg_stream *state,poly *z,poly *v,size_t len,long double var,long double m);
int quil_is_rejected_bimodal1_stream(quil_prg_stream *state,poly *z,poly *v,size_t len,long double var,long double m);

#endif
