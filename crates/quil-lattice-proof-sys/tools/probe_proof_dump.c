#include <assert.h>
#include <stdlib.h>
#include "malloc.h"
#include "fixture_proof_dump.h"
#include "fixture_proof_encode.h"
static void fill(polz *p,size_t n,int64_t value){
  polzvec_setzero(p,n);
  for(size_t i=0;i<n;i++){
    polz_setcoeff_fromint64(p[i],value+(int64_t)i,0);
    polz_setcoeff_fromint64(p[i],-1,N-1);
  }
}
int main(int argc,char **argv){
  assert(argc==2 || argc==4);
  int status=0;
  dch_pack_params params={0};dch_pack_proof proof={0};
  params->pp_dch->nquad=1;params->pp_dch->kappa_outer=1;
  proof->pi_dch->com=_aligned_alloc(64,sizeof(polz));fill(proof->pi_dch->com,1,13);
  params->pp_pack->np=4;params->pp_pack->zkround=2;
  params->pp_pack->p=calloc(4,sizeof(lab_params));
  params->pp_pack->zkp=calloc(1,sizeof(lnp_params));
  params->pp_pack->zkp[0]->kappa_linfmsis=1;
  params->pp_pack->p[0]->compressed=1;params->pp_pack->p[0]->kappa[2]=2;
  params->pp_pack->p[1]->kappa[1]=1;
  params->pp_pack->p[3]->tail=1;
  params->pp_pack->p[3]->fz=2;params->pp_pack->p[3]->nmax=2;
  for(int i=LAB_INCOM;i<=LAB_LING;i++)params->pp_pack->p[3]->len[i]=1;
  params->pp_pack->p[3]->len[LAB_LIFT]=LIFTS;
  pack_proof_init(proof->pi_pack,params->pp_pack);
  memset(proof->pi_pack->p,0,4*sizeof(lab_proof));
  for(int i=0;i<4;i++){
    if(i==2)continue;
    lab_proof_init(proof->pi_pack->p[i],params->pp_pack->p[i]);
    size_t count=i==0 ? 8 : (i==1 ? 2+LIFTS : 3+LIFTS);
    fill(proof->pi_pack->p[i]->m[0],count,10*i+20);
    for(int j=0;j<256;j++)proof->pi_pack->p[i]->p[j]=j-128;
  }
  lnp_proof_init(proof->pi_pack->zkp[0],params->pp_pack->zkp[0]);
  fill(proof->pi_pack->zkp[0]->m[0],5,50);
  lab_witness_init(proof->pi_pack->owt,params->pp_pack->p[3]);
  for(int i=0;i<4;i++)for(int j=0;j<N;j++)proof->pi_pack->owt->s[0][i]->c[j]=j%2 ? -32768 : 32767;
  assert(fixture_dump_proof(argv[1],proof,params));
  if(argc==4){
    FILE *f=fopen(argv[2],"rb");assert(f);
    assert(fseek(f,0,SEEK_END)==0);long size=ftell(f);assert(size>=0 && size<FIXTURE_PROOF_LIMIT);rewind(f);
    uint8_t *bytes=malloc(size ? (size_t)size : 1);assert(bytes);
    assert(fread(bytes,1,(size_t)size,f)==(size_t)size);assert(fclose(f)==0);
    dch_pack_proof decoded;
    if(!fixture_decode_proof(decoded,params,bytes,(size_t)size))status=2;
    else{
      assert(fixture_dump_proof(argv[3],decoded,params));
      uint8_t *encoded=malloc(size);assert(encoded);size_t written=99;
      assert(!fixture_encode_proof(encoded,(size_t)size-1,&written,decoded,params));
      assert(written==0);
      assert(fixture_encode_proof(encoded,(size_t)size,&written,decoded,params));
      assert(written==(size_t)size && !memcmp(encoded,bytes,written));
      /* No noncanonical native representative may enter the wire encoding. */
      polz_setcoeff_fromint64(decoded->pi_dch->com[0],-1,0);
      assert(!fixture_encode_proof(encoded,(size_t)size,&written,decoded,params));
      assert(written==0);
      free(encoded);fixture_decoded_free(decoded);
    }
    free(bytes);
  }
  lnp_proof_free(proof->pi_pack->zkp[0]);
  pack_proof_free(proof->pi_pack);dch_proof_free(proof->pi_dch);
  free(params->pp_pack->p);free(params->pp_pack->zkp);
  return status;
}
