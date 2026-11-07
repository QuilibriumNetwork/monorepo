#ifndef QUIL_PUBLIC_COEFFICIENT_ENCODING_H
#define QUIL_PUBLIC_COEFFICIENT_ENCODING_H
#include <stddef.h>
#include <stdint.h>
#include "data.h"

/* Canonical coefficient encoding for native-public-statement/v4.
 * Tags: 0 = zero, 1 = sparse, 2 = dense. All contain a u16 LE count.
 * Sparse adds a u16 nonzero count and increasing (u16 index, QBYTES value)
 * records. Dense stores every QBYTES value. Values are canonical modulo q.
 * Sparse is selected only when strictly shorter than dense; zero has tag 0.
 * Thus decoding recovers both count and every coefficient unambiguously.
 */
static size_t quil_encode_public_coefficients(uint8_t *out,size_t capacity,
                                             const int64_t *values,size_t count) {
  if(!out || !values || !count || count>N || capacity<3+count*QBYTES)return 0;
  const int64_t q=((int64_t)1<<LOGQ)-QOFF;
  uint64_t normalized[N];size_t nonzero=0;
  for(size_t i=0;i<count;i++) {
    int64_t v=values[i]%q;if(v<0)v+=q;
    normalized[i]=(uint64_t)v;nonzero+=(v!=0);
  }
  out[1]=(uint8_t)count;out[2]=(uint8_t)(count>>8);
  size_t pos=3;
  if(!nonzero){out[0]=0;return pos;}
  int sparse=2+nonzero*(2+QBYTES)<count*QBYTES;
  out[0]=sparse ? 1 : 2;
  if(sparse){out[pos++]=(uint8_t)nonzero;out[pos++]=(uint8_t)(nonzero>>8);}
  for(size_t i=0;i<count;i++) {
    if(sparse) {
      if(!normalized[i])continue;
      out[pos++]=(uint8_t)i;out[pos++]=(uint8_t)(i>>8);
    }
    uint64_t value=normalized[i];
    for(size_t j=0;j<QBYTES;j++){out[pos++]=(uint8_t)value;value>>=8;}
  }
  return pos;
}
#endif
