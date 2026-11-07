/* Bound propagation only; does not alter sampled coefficients. */
#ifndef QUIL_PROBE_MASK_WIDTH_H
#define QUIL_PROBE_MASK_WIDTH_H
#include <assert.h>
#include <math.h>
#include "polz.h"
static void probe_mask_width(polxvec target, const polz *source, size_t len,
                             unsigned int logsd) {
  assert(logsd <= 31);
  /* Public envelope, wider than 14 * 1.55 * 2^logsd, capped at i32 range.
     Validate it explicitly; never clip or resample an out-of-range value. */
  unsigned int bits = logsd + 6;
  if(bits > 31) bits = 31;
  int64_t bound = (int64_t)1 << bits;
  for(size_t i=0;i<len;i++) for(int j=0;j<N;j++) {
    zz coefficient;
    polz_getcoeff(coefficient,source[i],j);
    int64_t value = int64_fromzz(coefficient);
    assert(value >= -bound && value < bound);
  }
  polxvec_setwidths1(target,0,1,len,ldexp(1.0,2*bits));
}
#endif
