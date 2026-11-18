/* QPF6 decoder. All dimensions come from verifier parameters.
 * No untrusted body dimension controls an allocation. Not an active node API.
 */
#ifndef QUIL_FIXTURE_PROOF_DECODE_H
#define QUIL_FIXTURE_PROOF_DECODE_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "malloc.h"
#include "fips202.h"
#include "dachshund.h"
#define FIXTURE_PROOF_LIMIT (1u<<20)
static void fixture_u32(uint8_t **p,uint32_t value){for(int i=0;i<4;i++){*(*p)++=value&255;value>>=8;}}
static int fixture_message_lengths(size_t counts[4],const lab_params p){
  if(p->compressed && p->tail)return 0;
  if(p->compressed){for(int i=0;i<4;i++)counts[i]=p->kappa[2];}
  else if(!p->tail){counts[0]=p->kappa[1];counts[1]=0;counts[2]=LIFTS;counts[3]=p->kappa[1];}
  else{
    if(p->len[LAB_INCOM]>1024 || p->len[LAB_QUADG]>1024)return 0;
    counts[0]=p->len[LAB_INCOM]+p->len[LAB_QUADG];counts[1]=0;counts[2]=p->len[LAB_LIFT];counts[3]=p->len[LAB_LING];
  }
  for(int i=0;i<4;i++)if(counts[i]>1024)return 0;
  return 1;
}
static int fixture_expected_header(uint8_t header[40],size_t *size,const dch_pack_params params){
  const size_t np=params->pp_pack->np,zk=params->pp_pack->zkround;
  if(N!=256 || LOGQ!=38 || np<2 || np>64 || zk>=np-1 || !params->pp_pack->zkp)return 0;
  const lab_params *last=&params->pp_pack->p[np-1];
  if(!(*last)->tail || (*last)->compressed || (*last)->fz<1 || (*last)->fz>2 || !(*last)->nmax || (*last)->nmax>2048)return 0;
  size_t dc=(params->pp_dch->nexact || params->pp_dch->nquad) ? params->pp_dch->kappa_outer : 0;
  if(dc>1024)return 0;
  uint8_t descriptor[2048],*p=descriptor;
  static const uint8_t domain[]="quil/proof-shape/v1";
  memcpy(p,domain,sizeof(domain));p+=sizeof(domain);
  fixture_u32(&p,np);fixture_u32(&p,zk);fixture_u32(&p,dc);
  size_t bytes=40+dc*1216;
  for(size_t i=0;i<np;i++){
    if(i==zk){memset(p,0,21);p+=21;continue;}
    const lab_params *round=&params->pp_pack->p[i];size_t counts[4];
    if(!fixture_message_lengths(counts,*round))return 0;
    *p++=(*round)->compressed ? 1 : ((*round)->tail ? 3 : 2);
    fixture_u32(&p,(*round)->tail ? (*round)->len[LAB_INCOM] : 0);
    for(int j=0;j<4;j++){fixture_u32(&p,counts[j]);bytes+=counts[j]*1216;}
    if(!(*round)->compressed)bytes+=1024;
  }
  size_t rank=params->pp_pack->zkp[0]->kappa_linfmsis;
  if(!rank || rank>1024)return 0;
  for(int j=0;j<5;j++){size_t n=j==2 ? 1 : rank;fixture_u32(&p,n);bytes+=n*1216;}
  fixture_u32(&p,(*last)->fz);
  for(size_t i=0;i<(*last)->fz;i++){fixture_u32(&p,(*last)->nmax);bytes+=(*last)->nmax*512;}
  if(bytes>=FIXTURE_PROOF_LIMIT)return 0;
  memcpy(header,"QPF6\0\0\0\0",8);
  shake256(header+8,32,descriptor,(size_t)(p-descriptor));
  *size=bytes;return 1;
}
static int fixture_read_polys(polz *out,size_t count,size_t center_start,const uint8_t **cursor){
  const uint64_t q=((uint64_t)1<<38)-107;
  for(size_t i=0;i<count;i++){
    uint64_t bits=0;unsigned int available=0;
    for(int j=0;j<N;j++){
      while(available<38){bits|=(uint64_t)*(*cursor)++<<available;available+=8;}
      uint64_t value=bits&(((uint64_t)1<<38)-1);bits>>=38;available-=38;
      if(value>=q)return 0;
      int64_t coefficient=(int64_t)value;
      if(i>=center_start && value>q/2)coefficient-=(int64_t)q;
      polz_setcoeff_fromint64(out[i],coefficient,j);
    }
    if(available!=0)return 0;
  }
  return 1;
}
static void fixture_decoded_free(dch_pack_proof proof){
  if(proof->pi_pack->zkp)lnp_proof_free(proof->pi_pack->zkp[0]);
  dch_pack_proof_free(proof);
  memset(proof,0,sizeof(*proof));
}
static int fixture_decode_proof(dch_pack_proof proof,const dch_pack_params params,const uint8_t *bytes,size_t size){
  uint8_t header[40];size_t expected;
  memset(proof,0,sizeof(*proof));
  if(!bytes || !fixture_expected_header(header,&expected,params) || size!=expected || memcmp(bytes,header,40))return 0;
  const uint8_t *cursor=bytes+40;
  size_t np=params->pp_pack->np,zk=params->pp_pack->zkround;
  pack_proof_init(proof->pi_pack,params->pp_pack);
  memset(proof->pi_pack->p,0,np*sizeof(lab_proof));
  memset(proof->pi_pack->zkp,0,sizeof(lnp_proof));
  /* Allocate every bounded field before decoding, so cleanup also covers failures. */
  lab_witness_init(proof->pi_pack->owt,params->pp_pack->p[np-1]);
  size_t dc=(params->pp_dch->nexact || params->pp_dch->nquad) ? params->pp_dch->kappa_outer : 0;
  if(dc)proof->pi_dch->com=_aligned_alloc(64,dc*sizeof(polz));
  for(size_t i=0;i<np;i++)if(i!=zk)lab_proof_init(proof->pi_pack->p[i],params->pp_pack->p[i]);
  lnp_proof_init(proof->pi_pack->zkp[0],params->pp_pack->zkp[0]);
  if(!fixture_read_polys(proof->pi_dch->com,dc,SIZE_MAX,&cursor))goto invalid;
  for(size_t i=0;i<np;i++){
    if(i==zk)continue;
    const lab_params *p=&params->pp_pack->p[i];size_t counts[4];
    if(!fixture_message_lengths(counts,*p))goto invalid;
    for(int j=0;j<4;j++)if(!fixture_read_polys(proof->pi_pack->p[i]->m[j],counts[j],(*p)->tail && j==0 ? (*p)->len[LAB_INCOM] : SIZE_MAX,&cursor))goto invalid;
    if(!(*p)->compressed)for(int j=0;j<256;j++){
      uint32_t v=0;for(int k=0;k<4;k++)v|=(uint32_t)*cursor++<<(8*k);
      proof->pi_pack->p[i]->p[j]=(int32_t)(v<=INT32_MAX ? (int64_t)v : (int64_t)v-((int64_t)1<<32));
    }
  }
  for(int j=0;j<5;j++)if(!fixture_read_polys(proof->pi_pack->zkp[0]->m[j],j==2 ? 1 : params->pp_pack->zkp[0]->kappa_linfmsis,j==2 ? 0 : SIZE_MAX,&cursor))goto invalid;
  for(size_t i=0;i<proof->pi_pack->owt->r;i++)for(size_t j=0;j<proof->pi_pack->owt->n[i];j++)for(int k=0;k<N;k++){
    uint32_t v=cursor[0]|((uint32_t)cursor[1]<<8);cursor+=2;
    proof->pi_pack->owt->s[i][j]->c[k]=(int16_t)(v<=INT16_MAX ? (int32_t)v : (int32_t)v-65536);
  }
  if((size_t)(cursor-bytes)!=size)goto invalid;
  return 1;
invalid:
  fixture_decoded_free(proof);return 0;
}
#endif
