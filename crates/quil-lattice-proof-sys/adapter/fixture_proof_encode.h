/* Bounded QPF6 encoder, paired with the independent Python codec. */
#ifndef QUIL_FIXTURE_PROOF_ENCODE_H
#define QUIL_FIXTURE_PROOF_ENCODE_H
#include "fixture_proof_decode.h"
static int fixture_write_polys(uint8_t **cursor,const polz *input,size_t count,size_t center_start) {
  const int64_t q=((int64_t)1<<38)-107;
  if(count && !input)return 0;
  for(size_t i=0;i<count;i++) {
    uint64_t bits=0;unsigned available=0;
    for(int j=0;j<N;j++) {
      zz coefficient,rebuilt;
      polz_getcoeff(coefficient,input[i],j);
      int64_t value=int64_fromzz(coefficient);
      zz_fromint64(rebuilt,value);
      if(memcmp(coefficient->limbs,rebuilt->limbs,sizeof(coefficient->limbs)))return 0;
      if(i>=center_start) {
        if(value < -(q/2) || value > q/2)return 0;
      } else if(value<0 || value>=q)return 0;
      if(value<0)value+=q;
      bits|=(uint64_t)value<<available;available+=38;
      while(available>=8){*(*cursor)++=(uint8_t)bits;bits>>=8;available-=8;}
    }
    if(available)return 0;
  }
  return 1;
}
static int fixture_encode_proof(uint8_t *bytes,size_t capacity,size_t *written,
                                const dch_pack_proof proof,const dch_pack_params params) {
  uint8_t header[40];size_t expected;
  if(!written)return 0;
  *written=0;
  if(!bytes || !fixture_expected_header(header,&expected,params) || capacity<expected)return 0;
  size_t np=params->pp_pack->np,zk=params->pp_pack->zkround;
  const lab_params *tail=&params->pp_pack->p[np-1];
  if(proof->pi_pack->np!=np || !proof->pi_pack->p || !proof->pi_pack->zkp ||
     proof->pi_pack->owt->r!=(*tail)->fz)return 0;
  for(size_t i=0;i<proof->pi_pack->owt->r;i++)
    if(proof->pi_pack->owt->n[i]!=(*tail)->nmax || !proof->pi_pack->owt->s[i])return 0;
  memcpy(bytes,header,40);uint8_t *cursor=bytes+40;
  size_t dc=(params->pp_dch->nexact || params->pp_dch->nquad) ? params->pp_dch->kappa_outer : 0;
  if(!fixture_write_polys(&cursor,proof->pi_dch->com,dc,SIZE_MAX))return 0;
  for(size_t i=0;i<np;i++) {
    if(i==zk)continue;
    const lab_params *p=&params->pp_pack->p[i];size_t counts[4];
    if(!fixture_message_lengths(counts,*p))return 0;
    for(int j=0;j<4;j++)
      if(!fixture_write_polys(&cursor,proof->pi_pack->p[i]->m[j],counts[j],
          (*p)->tail && j==0 ? (*p)->len[LAB_INCOM] : SIZE_MAX))return 0;
    if(!(*p)->compressed)for(int j=0;j<256;j++)
      fixture_u32(&cursor,(uint32_t)proof->pi_pack->p[i]->p[j]);
  }
  for(int j=0;j<5;j++)
    if(!fixture_write_polys(&cursor,proof->pi_pack->zkp[0]->m[j],
        j==2 ? 1 : params->pp_pack->zkp[0]->kappa_linfmsis,j==2 ? 0 : SIZE_MAX))return 0;
  for(size_t i=0;i<proof->pi_pack->owt->r;i++)
    for(size_t j=0;j<proof->pi_pack->owt->n[i];j++)for(int k=0;k<N;k++) {
      uint16_t value=(uint16_t)proof->pi_pack->owt->s[i][j]->c[k];
      *cursor++=(uint8_t)value;*cursor++=(uint8_t)(value>>8);
    }
  if((size_t)(cursor-bytes)!=expected)return 0;
  *written=expected;
  return 1;
}
#endif
