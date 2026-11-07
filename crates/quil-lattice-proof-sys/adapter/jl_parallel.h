#ifndef QUIL_JL_PARALLEL_H
#define QUIL_JL_PARALLEL_H
#include <stdio.h>
#include "proofsystem.h"
#include "jlproj.h"
#include "fips202.h"
#include "zq_parallel.h"

typedef struct {
  struct polxvec_str *matrix,*projection;
  const uint8_t *input1,*input2;
  size_t bits;
  int64_t challenge[256] __attribute__((aligned(64)));
} quil_jl_job;
static void *quil_jl_execute(void *opaque) {
  quil_jl_job *job=opaque;
  jl_aggregate_mat(job->matrix,job->input1,job->input2,job->challenge);
  jl_aggregate_proj(job->projection,job->bits,job->challenge);
  return NULL;
}
static size_t quil_jl_batch_size(size_t nmax) {
  if(nmax<256)return 1;
  size_t count=quil_native_thread_limit();
  // Bound concurrent temporary matrix copies to 128 MiB. This excludes the
  // shared inputs and retained outputs. Oversized individual jobs stay serial.
  size_t budget=128U*1024U*1024U,per_poly=K*sizeof(poly)+sizeof(double);
  if(nmax>budget/per_poly)return 1;
  size_t bytes=nmax*per_poly;
  while(count>1 && bytes>budget/count)count--;
  return count;
}
static void quil_collapse_jl(polxvec matrices[LIFTS],polxvec projections[LIFTS],
                             size_t nmax,size_t bits,const uint8_t *input1,
                             const uint8_t *input2,uint8_t h[HASHLEN]) {
  uint8_t hashbuf[64+QBYTES*256+24] __attribute__((aligned(64)));
  size_t batch=quil_jl_batch_size(nmax);
  const char *trace=getenv("QUIL_NATIVE_RESOURCE_TRACE");
  if(trace && !strcmp(trace,"1")) {
    fprintf(stderr,"quil_native_jl_shape nmax=%zu batch_size=%zu\n",nmax,batch);
    fflush(stderr);
  }
  for(size_t base=0;base<LIFTS;base+=batch) {
    size_t count=MIN(batch,LIFTS-base);
    quil_jl_job jobs[QUIL_ZQ_MAX_JOBS];
    pthread_t threads[QUIL_ZQ_MAX_JOBS];
    int started[QUIL_ZQ_MAX_JOBS]={0};
    // Preserve the original hash chain and challenge expansion order exactly.
    for(size_t slot=0;slot<count;slot++) {
      size_t i=base+slot;
      shake128(hashbuf,sizeof(hashbuf),h,HASHLEN);
      memcpy(h,hashbuf,HASHLEN);
      jlproj_expand_challenge(jobs[slot].challenge,&hashbuf[64]);
      polxvec_init(matrices[i],nmax,1);
      polxvec_init(projections[i],bits*256/N,1);
      jobs[slot].matrix=matrices[i];jobs[slot].projection=projections[i];
      jobs[slot].input1=input1;jobs[slot].input2=input2;jobs[slot].bits=bits;
    }
    // Workers read shared matrices and write disjoint owning outputs. Sampling,
    // transcript updates and allocation of outputs have already finished.
    for(size_t slot=1;slot<count;slot++) {
      if(!pthread_create(&threads[slot],NULL,quil_jl_execute,&jobs[slot]))started[slot]=1;
      else quil_jl_execute(&jobs[slot]);
    }
    quil_jl_execute(&jobs[0]);
    for(size_t slot=1;slot<count;slot++)
      if(started[slot] && pthread_join(threads[slot],NULL))abort();
  }
}
#endif
