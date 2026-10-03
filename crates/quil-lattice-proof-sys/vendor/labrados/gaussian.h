#ifndef GAUSSIAN_H
#define GAUSSIAN_H
#include "aesctr.h"
#include "prg_stream.h"
#define QUIL_PRIVATE_GAUSSIAN_MAX_COEFFICIENTS (1u << 24)
typedef int (*quil_gaussian_sampler)(const uint8_t *,uint64_t,unsigned int,unsigned int,int32_t *);
/* Registration and use require the process-wide native-state lock. */
void quil_set_private_gaussian_sampler(quil_gaussian_sampler sampler);
int quil_gaussian_private_i32(int32_t *out,unsigned int count,const uint8_t seed[32],uint64_t nonce,unsigned int scale);

void
gaussian_i32 (int32_t *ret, unsigned int nelems, aes128ctr_ctx *state,
                        unsigned int log2sd);

/* 0=success, -1=invalid dimensions/scale; error consumes no randomness. */
int quil_gaussian_i32_stream(int32_t *ret, unsigned int nelems,
                             quil_prg_stream *state, unsigned int log2sd);
#endif
