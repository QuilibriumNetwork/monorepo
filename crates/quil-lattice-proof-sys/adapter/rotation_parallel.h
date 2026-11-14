#ifndef QUIL_ROTATION_PARALLEL_H
#define QUIL_ROTATION_PARALLEL_H
#include "zq_parallel.h"

/* Commitment aggregation only: shared key/challenges are read-only, and each
 * worker owns whole rotation blocks in the output. Retain the original serial
 * routine within each block, including its intermediate refresh schedule. */
typedef struct { polxvec out, challenge, key; } quil_rotation_job;
static void *quil_rotation_execute(void *opaque) {
  quil_rotation_job *job=opaque;
  polxvec_rotation_aggregate_add(job->out,job->challenge,job->key);
  return NULL;
}
static void quil_polxvec_parallel_rotation_add(polxvec out,const polxvec challenge,
                                              const polxvec key) {
  size_t count=quil_native_thread_limit(),degree=next2power(challenge->len);
  if(out->len<256 || out->stride!=1 || key->stride!=1 || count==1 || !degree) {
    polxvec_rotation_aggregate_add(out,challenge,key);
    return;
  }
  size_t blocks=out->len/degree+(out->len%degree!=0);
  if(count>blocks)count=blocks;
  /* The serial helper allocates three degree-sized polynomial vectors. Bound
   * their combined concurrent storage, excluding existing shared inputs. */
  size_t budget=16U*1024U*1024U,bytes_per_degree=3*(K*sizeof(poly)+sizeof(double));
  if(degree>budget/bytes_per_degree || blocks>key->len/degree)count=1;
  else while(count>1 && degree*bytes_per_degree>budget/count)count--;
  if(count<2) {
    polxvec_rotation_aggregate_add(out,challenge,key);
    return;
  }
  quil_rotation_job jobs[QUIL_ZQ_MAX_JOBS];
  pthread_t threads[QUIL_ZQ_MAX_JOBS];
  int started[QUIL_ZQ_MAX_JOBS]={0};
  size_t offset=0;
  for(size_t i=0;i<count;i++) {
    size_t span=(blocks/count+(i<blocks%count))*degree;
    size_t length=MIN(span,out->len-offset);
    polxvec_init_subvec2(jobs[i].out,out,offset,1,length);
    polxvec_init_subvec2(jobs[i].key,key,offset,1,span);
    polxvec_init_subvec2(jobs[i].challenge,challenge,0,1,challenge->len);
    offset+=length;
  }
  for(size_t i=1;i<count;i++) {
    if(!pthread_create(&threads[i],NULL,quil_rotation_execute,&jobs[i]))started[i]=1;
    else quil_rotation_execute(&jobs[i]);
  }
  quil_rotation_execute(&jobs[0]);
  for(size_t i=1;i<count;i++)
    if(started[i] && pthread_join(threads[i],NULL))abort();
}
#endif
