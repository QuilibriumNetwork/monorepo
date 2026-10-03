#ifndef QUIL_PRIVATE_SAMPLING_PARAMS_H
#define QUIL_PRIVATE_SAMPLING_PARAMS_H
#include <math.h>
#define QUIL_PRIVATE_REJECTION_TAIL 14

/* Public parameter quantization for the reviewed private sampler family.
 * Outputs remain unchanged on error. The literal 1.55 intentionally retains
 * the existing binary64 value, promoted to long double. */
static inline int quil_private_sampling_params(
    long double *capm, unsigned int *log2sd, long double *sd,
    long double *gamma, long double t, int sign_leak)
{
    if (!capm || !log2sd || !sd || !gamma ||
        !isfinite(*sd) || *sd <= 0 || !isfinite(t) || t <= 0 ||
        (sign_leak != 0 && sign_leak != 1)) return 1;
    long double scale = log2l(*sd / (long double)1.55);
    scale = sign_leak ? ceill(scale) : roundl(scale);
    /* Validate before float-to-integer conversion, and avoid integer shifts. */
    if (!isfinite(scale) || scale < 0 || scale > 26) return 1;
    unsigned int exponent = (unsigned int)scale;
    long double rounded = ldexpl((long double)1.55, (int)exponent);
    long double ratio = rounded / t;
    if (!isfinite(ratio) || ratio <= 0) return 1;
    long double envelope = expl((sign_leak ? 0 : QUIL_PRIVATE_REJECTION_TAIL / ratio) + 1 / (2 * ratio * ratio));
    if (!isfinite(envelope) || envelope < 1) return 1;
    *capm = envelope;
    *log2sd = exponent;
    *sd = rounded;
    *gamma = ratio;
    return 0;
}
#endif
