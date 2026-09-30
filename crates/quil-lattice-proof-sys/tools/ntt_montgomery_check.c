/* Standalone integer-reference diagnostic for the bounded ARM kernels.
 * Compile against the repository data.c and shim/SIMDe include paths.
 * This validates bounded kernels, not their integration or performance.
 */
#include <arm_neon.h>
#include <stdio.h>
#include <limits.h>
#include "data.h"

#include "arm_montgomery.h"

static int32_t floor_high(int32_t product) {
  return product>=0 ? product/65536 : -((-(int64_t)product+65535)/65536);
}
static int32_t signed_low(int32_t product) {
  uint32_t low=(uint32_t)product&65535;
  return low<32768 ? (int32_t)low : (int32_t)low-65536;
}
int main(void) {
  size_t pairs=0;
  for(size_t k=0;k<K;k++) {
    int p=primes[k]->p,pinv=primes[k]->pinv;
    if(p<=0 || p>=16384 || ((uint32_t)(p*pinv)&65535)!=1)return 1;
    int factors[N+9];
    for(size_t i=0;i<N;i++)factors[i]=primes[k]->zetas->c[i];
    int extra[]={-p,1-p,-1,0,1,p-1,p,primes[k]->i,primes[k]->f};
    for(size_t i=0;i<9;i++)factors[N+i]=extra[i];
    for(size_t factor=0;factor<N+9;factor++) {
      int b=factors[factor],bpinv=signed_low(b*pinv);
      if(b < -p || b > p)return 2;
      if(factor<N && bpinv!=primes[k]->zetas_pinv->c[factor])return 3;
      for(int first=INT16_MIN;first<=INT16_MAX;first+=8) {
        int16_t a[8],product[8],divided[8];
        for(int lane=0;lane<8;lane++)a[lane]=first+lane;
        int16x8_t aa=vld1q_s16(a),pp=vdupq_n_s16(p);
        vst1q_s16(product,quil_arm_mulmod(aa,vdupq_n_s16(b),vdupq_n_s16(bpinv),pp));
        vst1q_s16(divided,quil_arm_divmont(aa,pp,vdupq_n_s16(pinv)));
        for(int lane=0;lane<8;lane++) {
          int t=signed_low(a[lane]*bpinv);
          int expected=floor_high(a[lane]*b)-floor_high(t*p);
          int dt=signed_low(a[lane]*pinv);
          int expected_div=(a[lane]<0 ? -1 : 0)-floor_high(dt*p);
          if(product[lane]!=expected || divided[lane]!=expected_div) {
            fprintf(stderr,"mismatch prime=%d a=%d b=%d\n",p,a[lane],b);return 4;
          }
          pairs++;
        }
      }
    }
  }
  printf("bounded_montgomery_check passed pairs=%zu primes=%d\n",pairs,K);
  return 0;
}
