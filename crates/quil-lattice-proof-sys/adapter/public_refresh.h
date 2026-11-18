#ifndef QUIL_PUBLIC_REFRESH_H
#define QUIL_PUBLIC_REFRESH_H
#include <string.h>
#include "polx.h"
#include "constraints.h"

/* Public constraint coefficients only. Do not use this data-dependent shortcut
 * for witness/masking vectors. Exact raw-zero chunks retain the same canonical
 * representation and widths as the original refresh. Nonzero chunks use the
 * unmodified arithmetic, at the same 32-polynomial boundaries. */
static void quil_public_polxvec_refresh(polxvec value) {
  if(value->stride!=1 || value->len<32) {
    polxvec_refresh(value);
    return;
  }
  static const unsigned char zeros[32*sizeof(poly)]={0};
  polx canonical_zero;
  polx_setzero(canonical_zero);
  polx_refresh(canonical_zero);
  // Derive the canonical width through the reference arithmetic rather than
  // duplicating a parameter formula. Fail back if a backend encodes zero oddly.
  for(size_t p=0;p<K;p++)if(memcmp(canonical_zero->proj[p],zeros,sizeof(poly))) {
    polxvec_refresh(value);
    return;
  }
  for(size_t off=0;off<value->len;off+=32) {
    size_t length=MIN(32,value->len-off);
    int zero=1;
    for(size_t p=0;p<K;p++)if(memcmp(&value->proj[p][off],zeros,length*sizeof(poly))) {
      zero=0;
      break;
    }
    if(zero)polxvec_setwidths1(value,off,1,length,canonical_zero->width);
    else {
      polxvec part;
      polxvec_init_subvec2(part,value,off,1,length);
      polxvec_refresh(part);
    }
  }
}
static void quil_public_sparsecnst_refresh(sparsecnst value) {
  for(size_t i=0;i<value->quad->len;i++)polx_refresh(value->quad->coeffs[i]);
  for(size_t i=0;i<value->lin->nparts;i++)quil_public_polxvec_refresh(value->lin->phi[i]);
  polxvec_refresh(value->b);
}
#endif
