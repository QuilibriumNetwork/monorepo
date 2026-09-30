#ifndef QUIL_ARM_MONTGOMERY_H
#define QUIL_ARM_MONTGOMERY_H
#include <arm_neon.h>

/* For 0<p<2^14, |b|<=p and b_pinv=b*p^-1 mod 2^16:
 * low16(a*b)==low16(low16(a*b_pinv)*p). Their doubled high halves
 * therefore differ by an even value, exactly twice the original Montgomery
 * result. Each high half is bounded by p, so the subtraction cannot overflow.
 * Neither multiply can encounter the saturating INT16_MIN*INT16_MIN case.
 */
static inline int16x8_t quil_arm_mulmod(int16x8_t a,int16x8_t b,
                                int16x8_t b_pinv,int16x8_t p) {
  int16x8_t t=vmulq_s16(a,b_pinv);
  return vshrq_n_s16(vsubq_s16(vqdmulhq_s16(a,b),vqdmulhq_s16(t,p)),1);
}

/* Here low16(t*p)==low16(a). The odd bit of the doubled high product
 * equals the sign bit of a. Arithmetic shift of its negation recovers
 * sign(a)-hi16(t*p), including negative odd products. */
static inline int16x8_t quil_arm_divmont(int16x8_t a,int16x8_t p,int16x8_t pinv) {
  int16x8_t t=vmulq_s16(a,pinv);
  return vshrq_n_s16(vnegq_s16(vqdmulhq_s16(t,p)),1);
}

#endif
