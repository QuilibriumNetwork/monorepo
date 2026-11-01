#ifndef QUIL_PRIVATE_MASK_RANGE_H
#define QUIL_PRIVATE_MASK_RANGE_H

#include "polz.h"

/* Private Gaussian samples are signed i32 values. Check representability
 * before taking their low bits: truncation is not a valid mask conversion.
 * Failure aborts the enclosing proof; it must not resample this mask alone.
 */
static inline int quil_private_mask_fits(const polz *values, size_t len,
                                         unsigned int bits) {
  if(!bits || bits>32)return 0;
  const int64_t limit=INT64_C(1)<<(bits-1);
  for(size_t i=0;i<len;i++)for(size_t j=0;j<N;j++) {
    zz coefficient;
    polz_getcoeff(coefficient,values[i],j);
    const int64_t value=int64_fromzz(coefficient);
    if(value < -limit || value >= limit)return 0;
  }
  return 1;
}

#endif
