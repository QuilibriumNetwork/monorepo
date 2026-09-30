#ifndef QUIL_SHAKE_ABSORB_TEST_H
#define QUIL_SHAKE_ABSORB_TEST_H
#include "fips202.h"

/* The one-shot API uses keccak_absorb_once, independent of the modified
 * incremental absorber. Check every two-chunk split around two rate blocks,
 * varying pointer alignment, then bytewise and irregular streaming across
 * larger inputs with multi-block output. */
int quil_fixture_test_shake_absorption(void) {
  uint8_t input[2056],expected[512],actual[512];
  for(size_t i=0;i<sizeof(input);i++)input[i]=(uint8_t)(i*131+17);
  for(int variant=0;variant<2;variant++) {
    size_t rate=variant ? SHAKE256_RATE : SHAKE128_RATE;
    for(size_t len=0;len<=2*rate+9;len++) {
      for(size_t split=0;split<=len;split++) {
        const uint8_t *bytes=input+(split&7);
        shake128incctx ctx;
        if(variant) {
          shake256(expected,64,bytes,len);
          shake256_inc_init(&ctx);
          shake256_inc_absorb(&ctx,bytes,split);
          shake256_inc_absorb(&ctx,bytes+split,0);
          shake256_inc_absorb(&ctx,bytes+split,len-split);
          shake256_inc_finalize(&ctx);
          shake256_inc_squeeze(actual,64,&ctx);
        } else {
          shake128(expected,64,bytes,len);
          shake128_inc_init(&ctx);
          shake128_inc_absorb(&ctx,bytes,split);
          shake128_inc_absorb(&ctx,bytes+split,0);
          shake128_inc_absorb(&ctx,bytes+split,len-split);
          shake128_inc_finalize(&ctx);
          shake128_inc_squeeze(actual,64,&ctx);
        }
        if(memcmp(actual,expected,64))return 0;
      }
    }
    for(size_t alignment=0;alignment<8;alignment++) {
      for(size_t chunk=1;chunk<=173;chunk+=4) {
        const uint8_t *bytes=input+alignment;
        shake128incctx ctx;
        if(variant){shake256(expected,512,bytes,2048);shake256_inc_init(&ctx);}
        else {shake128(expected,512,bytes,2048);shake128_inc_init(&ctx);}
        for(size_t off=0;off<2048;) {
          size_t take=chunk<2048-off ? chunk : 2048-off;
          if(variant)shake256_inc_absorb(&ctx,bytes+off,take);
          else shake128_inc_absorb(&ctx,bytes+off,take);
          off+=take;
        }
        if(variant){shake256_inc_finalize(&ctx);shake256_inc_squeeze(actual,512,&ctx);}
        else {shake128_inc_finalize(&ctx);shake128_inc_squeeze(actual,512,&ctx);}
        if(memcmp(actual,expected,512))return 0;
      }
    }
  }
  return 1;
}
#endif
