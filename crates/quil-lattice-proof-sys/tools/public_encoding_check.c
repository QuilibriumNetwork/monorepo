/* Standalone reference and hashing-cost diagnostic for the active v2 codec. Compile with fips202.c and the normal include paths. */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include "public_coefficient_encoding.h"
#include "fips202.h"

static uint64_t read_le(const uint8_t *bytes,size_t count) {
  uint64_t value=0;
  for(size_t i=count;i;i--)value=(value<<8)|bytes[i-1];
  return value;
}
/* Separate decoder, including canonical-choice checks. */
static int decode(uint64_t *values,size_t *count,const uint8_t *bytes,size_t len) {
  if(len<3)return 0;
  size_t n=read_le(bytes+1,2),nonzero=0,pos=3;
  if(!n || n>N)return 0;
  memset(values,0,n*sizeof(*values));
  uint64_t q=((uint64_t)1<<LOGQ)-QOFF;
  if(bytes[0]==0){if(len!=3)return 0;}
  else if(bytes[0]==1) {
    if(len<5)return 0;
    nonzero=read_le(bytes+3,2);pos=5;
    if(!nonzero || nonzero>n || len!=5+nonzero*(2+QBYTES)
       || 2+nonzero*(2+QBYTES)>=n*QBYTES)return 0;
    size_t previous=0;
    for(size_t i=0;i<nonzero;i++) {
      size_t index=read_le(bytes+pos,2);pos+=2;
      uint64_t value=read_le(bytes+pos,QBYTES);pos+=QBYTES;
      if(index>=n || (i && index<=previous) || !value || value>=q)return 0;
      previous=index;values[index]=value;
    }
  } else if(bytes[0]==2) {
    if(len!=3+n*QBYTES)return 0;
    for(size_t i=0;i<n;i++) {
      values[i]=read_le(bytes+pos,QBYTES);pos+=QBYTES;
      if(values[i]>=q)return 0;
      nonzero+=(values[i]!=0);
    }
    if(!nonzero || 2+nonzero*(2+QBYTES)<n*QBYTES)return 0;
  } else return 0;
  *count=n;return 1;
}
static double seconds(void) {
  struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
  return (double)t.tv_sec+t.tv_nsec/1e9;
}
int main(void) {
  int64_t values[N],equivalent[N];uint64_t decoded[N];
  uint8_t encoded[3+N*QBYTES],again[3+N*QBYTES];
  int64_t q=((int64_t)1<<LOGQ)-QOFF;
  size_t checks=0;
  for(size_t count=1;count<=N;count++)for(size_t occupied=0;occupied<=count;occupied++) {
    for(size_t i=0;i<count;i++) {
      values[i]=i<occupied ? ((i&1) ? -(int64_t)(i+1) : (int64_t)(i+1)) : 0;
      equivalent[i]=values[i]+q;
    }
    size_t len=quil_encode_public_coefficients(encoded,sizeof(encoded),values,count),n=0;
    size_t len2=quil_encode_public_coefficients(again,sizeof(again),equivalent,count);
    if(!len || len!=len2 || memcmp(encoded,again,len) || !decode(decoded,&n,encoded,len) || n!=count)return 1;
    for(size_t i=0;i<count;i++) {
      int64_t v=values[i]%q;if(v<0)v+=q;
      if(decoded[i]!=(uint64_t)v)return 2;
    }
    checks++;
  }
  for(size_t i=0;i<N;i++)values[i]=(i&1) ? INT64_MIN : INT64_MAX;
  size_t len=quil_encode_public_coefficients(encoded,sizeof(encoded),values,N),n;
  if(!decode(decoded,&n,encoded,len))return 3;
  for(size_t i=0;i<N;i++) {int64_t v=values[i]%q;if(v<0)v+=q;if(decoded[i]!=(uint64_t)v)return 4;}
  memset(values,0,sizeof(values));values[N-1]=-1;
  len=quil_encode_public_coefficients(encoded,sizeof(encoded),values,N);
#if LOGQ == 38
  const uint8_t expected[]={1,0,1,1,0,255,0,0x94,0xff,0xff,0xff,0x3f};
  if(len!=sizeof(expected) || memcmp(encoded,expected,len))return 5;
#endif
  /* Decoder rejects noncanonical records and incomplete encodings. */
  memcpy(again,encoded,len);
  if(decode(decoded,&n,again,len-1) || decode(decoded,&n,again,len+1))return 6;
  again[0]=3;if(decode(decoded,&n,again,len))return 7;
  memcpy(again,encoded,len);again[5]=0;again[6]=1;
  if(decode(decoded,&n,again,len))return 8;
  memcpy(again,encoded,len);memset(again+7,0,QBYTES);
  if(decode(decoded,&n,again,len))return 9;
  memcpy(again,encoded,len);
  for(size_t j=0;j<QBYTES;j++)again[7+j]=(uint8_t)((uint64_t)q>>(8*j));
  if(decode(decoded,&n,again,len))return 10;
  memset(again,0,sizeof(again));again[0]=1;again[2]=1;again[3]=2;
  again[5]=7;again[7]=1;again[7+QBYTES]=7;again[9+QBYTES]=1;
  if(decode(decoded,&n,again,5+2*(2+QBYTES)))return 11;
  memset(again,0,sizeof(again));again[0]=2;again[2]=1;
  if(decode(decoded,&n,again,3+N*QBYTES))return 12;
  printf("public_encoding_check checks=%zu boundary_values=passed pinned_monomial=passed noncanonical_rejection=passed\n",checks);
  const size_t rounds=100000;
  for(int pattern=0;pattern<3;pattern++) {
    memset(values,0,sizeof(values));
    if(pattern==1)values[N-1]=-1;
    if(pattern==2)for(size_t i=0;i<N;i++)values[i]=i+1;
    for(int compact=0;compact<2;compact++) {
      double start=seconds();size_t absorbed=0;uint8_t digest[32]={0};
      for(size_t round=0;round<rounds;round++) {
        uint8_t dense[8*N];shake128incctx hash;size_t size;
        if(compact)size=quil_encode_public_coefficients(encoded,sizeof(encoded),values,N);
        else {
          size=8*N;
          for(size_t i=0;i<N;i++) {
            int64_t v=values[i]%q;if(v<0)v+=q;
            uint64_t value=(uint64_t)v;
            for(size_t j=0;j<8;j++){dense[8*i+j]=(uint8_t)value;value>>=8;}
          }
        }
        shake128_inc_init(&hash);shake128_inc_absorb(&hash,digest,16);
        shake128_inc_absorb(&hash,compact ? encoded : dense,size);
        shake128_inc_finalize(&hash);shake128_inc_squeeze(digest,32,&hash);absorbed+=size;
      }
      printf("public_encoding_hash pattern=%d compact=%d rounds=%zu bytes=%zu seconds=%.6f digest_prefix=%02x%02x\n",pattern,compact,rounds,absorbed,seconds()-start,digest[0],digest[1]);
    }
  }
  return 0;
}
