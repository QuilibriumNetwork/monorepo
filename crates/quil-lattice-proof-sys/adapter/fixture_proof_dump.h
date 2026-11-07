/* Lossless diagnostic export of public-fixture proofs, NOT a wire codec.
 * Export precedes verification so a later verifier failure does not lose data.
 */
#ifndef QUIL_FIXTURE_PROOF_DUMP_H
#define QUIL_FIXTURE_PROOF_DUMP_H
#include <stdio.h>
#include <string.h>
#include "dachshund.h"
static int fixture_dump_polys(FILE *f,const polz *polys,size_t count) {
  if(count && !polys)return 0;
  fputc('[',f);
  for(size_t i=0;i<count;i++) {
    if(i)fputc(',',f);
    fputc('[',f);
    for(int j=0;j<N;j++) {
      zz coefficient;
      polz_getcoeff(coefficient,polys[i],j);
      int64_t value=int64_fromzz(coefficient);
      /* Verify that exporting the integer does not discard limb information. */
      zz rebuilt;zz_fromint64(rebuilt,value);
      if(memcmp(rebuilt->limbs,coefficient->limbs,sizeof(coefficient->limbs)))return 0;
      if(j)fputc(',',f);
      fprintf(f,"%lld",(long long)value);
    }
    fputc(']',f);
  }
  fputc(']',f);
  return !ferror(f);
}
static int fixture_dump_proof(const char *path,const dch_pack_proof proof,const dch_pack_params params) {
  if(!path || N!=256 || LOGQ!=38 || !params->pp_pack->zkp)return 0;
  FILE *f=fopen(path,"w");if(!f)return 0;
  int okay=0;
  fprintf(f,"{\"format\":\"quil-unverified-native-proof-fixture-v4\",\"degree\":256,\"modulus\":274877906837,\"dch_commitment\":");
  size_t count=(params->pp_dch->nexact || params->pp_dch->nquad) ? params->pp_dch->kappa_outer : 0;
  if(!fixture_dump_polys(f,proof->pi_dch->com,count))goto done;
  fprintf(f,",\"pack_round_count\":%zu,\"zk_round\":%zu,\"rounds\":[",params->pp_pack->np,params->pp_pack->zkround);
  for(size_t i=0;i<params->pp_pack->np;i++) {
    if(i)fputc(',',f);
    if(i==params->pp_pack->zkround){fputs("null",f);continue;}
    const lab_params *pp=&params->pp_pack->p[i];
    const lab_proof *pi=&proof->pi_pack->p[i];
    size_t lengths[4];
    if((*pp)->compressed)for(int j=0;j<4;j++)lengths[j]=(*pp)->kappa[2];
    else if(!(*pp)->tail){lengths[0]=(*pp)->kappa[1];lengths[1]=0;lengths[2]=LIFTS;lengths[3]=(*pp)->kappa[1];}
    else{lengths[0]=(*pp)->len[LAB_INCOM]+(*pp)->len[LAB_QUADG];lengths[1]=0;lengths[2]=(*pp)->len[LAB_LIFT];lengths[3]=(*pp)->len[LAB_LING];}
    fprintf(f,"{\"kind\":\"%s\",\"tail_inner_commitments\":%zu,\"messages\":[",(*pp)->compressed ? "compressed" : ((*pp)->tail ? "tail" : "uncompressed"),(*pp)->tail ? (*pp)->len[LAB_INCOM] : 0);
    for(int j=0;j<4;j++){
      if(j)fputc(',',f);
      if(!fixture_dump_polys(f,(*pi)->m[j],lengths[j]))goto done;
    }
    fputs("],\"projection\":",f);
    if((*pp)->compressed)fputs("null",f);
    else{
      fputc('[',f);
      for(int j=0;j<256;j++){if(j)fputc(',',f);fprintf(f,"%d",(*pi)->p[j]);}
      fputc(']',f);
    }
    fputc('}',f);
  }
  fputs("],\"lnp_messages\":[",f);
  for(int j=0;j<5;j++) {
    if(j)fputc(',',f);
    count=j==2 ? 256/N : params->pp_pack->zkp[0]->kappa_linfmsis;
    if(!fixture_dump_polys(f,proof->pi_pack->zkp[0]->m[j],count))goto done;
  }
  fputs("],\"final_witness\":[",f);
  for(size_t i=0;i<proof->pi_pack->owt->r;i++) {
    if(i)fputc(',',f);
    fputc('[',f);
    for(size_t j=0;j<proof->pi_pack->owt->n[i];j++){
      if(j)fputc(',',f);
      fputc('[',f);
      for(int k=0;k<N;k++){
        if(k)fputc(',',f);
        fprintf(f,"%d",proof->pi_pack->owt->s[i][j]->c[k]);
      }
      fputc(']',f);
    }
    fputc(']',f);
  }
  fputs("]}\n",f);
  okay=!ferror(f);
done:
  if(fclose(f))okay=0;
  return okay;
}
#endif
