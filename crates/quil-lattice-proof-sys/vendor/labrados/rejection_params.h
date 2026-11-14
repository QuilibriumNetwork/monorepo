/* Exact binary representation of public native sampling parameters. */
#ifndef QUIL_REJECTION_PARAMS_H
#define QUIL_REJECTION_PARAMS_H
#include <float.h>
#include <math.h>
#include <stdint.h>
#if defined(__FAST_MATH__) || __FINITE_MATH_ONLY__ > 0
#error "Native sampling parameters require finite checks and strict floating arithmetic"
#endif
_Static_assert(FLT_RADIX == 2 && LDBL_MANT_DIG <= 128,
               "Native sampling parameter encoding requires binary precision <=128");
_Static_assert(LDBL_MAX_EXP <= 16384 && LDBL_MIN_EXP >= -16381,
               "Native sampling parameter exponent outside reviewed bounds");

/* value = little_endian(mantissa) * 2^exponent. */
static inline int quil_rejection_binary_parts(long double value,uint8_t mantissa[16],int32_t *exponent) {
  if(!mantissa || !exponent || !isfinite(value) || value<=0)return -1;
  int e;
  long double fraction=frexpl(value,&e);
  long double high=ldexpl(fraction,64);
  uint64_t hi=(uint64_t)high;
  uint64_t lo=(uint64_t)ldexpl(high-(long double)hi,64);
  for(unsigned int i=0;i<8;i++) {
    mantissa[i]=(uint8_t)(lo>>(8*i));
    mantissa[i+8]=(uint8_t)(hi>>(8*i));
  }
  *exponent=e-128;
  return 0;
}
#endif
