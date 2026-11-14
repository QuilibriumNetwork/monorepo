#ifndef QUIL_REFRESH_PARALLEL_H
#define QUIL_REFRESH_PARALLEL_H
#include "zq_parallel.h"

/* Only for an exclusively owned output after aggregation workers have joined.
 * Each worker owns a disjoint contiguous slice, including its widths. Views are
 * stack metadata and are never freed. Arithmetic is the original refresh. */
typedef struct { polxvec value; } quil_refresh_job;
static void *quil_refresh_execute(void *opaque) {
  quil_refresh_job *job=opaque;
  polxvec_refresh(job->value);
  return NULL;
}
static void quil_polxvec_parallel_refresh(polxvec value) {
  size_t count=quil_native_thread_limit();
  if(value->len<256 || value->stride!=1 || count==1) {
    polxvec_refresh(value);
    return;
  }
  quil_refresh_job jobs[QUIL_ZQ_MAX_JOBS];
  pthread_t threads[QUIL_ZQ_MAX_JOBS];
  int started[QUIL_ZQ_MAX_JOBS]={0};
  size_t offset=0;
  for(size_t i=0;i<count;i++) {
    size_t length=value->len/count+(i<value->len%count);
    polxvec_init_subvec2(jobs[i].value,value,offset,1,length);
    offset+=length;
  }
  for(size_t i=1;i<count;i++) {
    if(!pthread_create(&threads[i],NULL,quil_refresh_execute,&jobs[i]))started[i]=1;
    else quil_refresh_execute(&jobs[i]);
  }
  quil_refresh_execute(&jobs[0]);
  for(size_t i=1;i<count;i++)
    if(started[i] && pthread_join(threads[i],NULL))abort();
}
static void quil_sparsecnst_parallel_refresh(sparsecnst cnst) {
  for(size_t i=0;i<cnst->quad->len;i++)polx_refresh(cnst->quad->coeffs[i]);
  for(size_t i=0;i<cnst->lin->nparts;i++)quil_polxvec_parallel_refresh(cnst->lin->phi[i]);
  quil_polxvec_parallel_refresh(cnst->b);
}

/* out[i] += scalar[0] * in[i] for every i, then refresh, split into contiguous
 * slices. polxvec_mul_add's width-overflow pre-refresh then applies per slice;
 * it only changes representation, never values, and the final refresh makes
 * every element canonical, so values and widths match the serial call. Inputs
 * are read-only and the slices are disjoint. */
typedef struct { polxvec out,in,scalar; } quil_mul_add_refresh_job;
static void *quil_mul_add_refresh_execute(void *opaque) {
  quil_mul_add_refresh_job *job=opaque;
  polxvec_mul_add(job->out,job->scalar,job->in);
  polxvec_refresh(job->out);
  return NULL;
}
static void quil_polxvec_parallel_mul_add_refresh(polxvec out,const polxvec scalar,
                                                  const polxvec in) {
  size_t count=quil_native_thread_limit();
  if(scalar->len!=1 || out->len!=in->len || out->len<256 || out->stride!=1
     || in->stride!=1 || count==1) {
    polxvec_mul_add(out,scalar,in);
    polxvec_refresh(out);
    return;
  }
  quil_mul_add_refresh_job jobs[QUIL_ZQ_MAX_JOBS];
  pthread_t threads[QUIL_ZQ_MAX_JOBS];
  int started[QUIL_ZQ_MAX_JOBS]={0};
  size_t offset=0;
  for(size_t i=0;i<count;i++) {
    size_t length=out->len/count+(i<out->len%count);
    polxvec_init_subvec2(jobs[i].out,out,offset,1,length);
    polxvec_init_subvec2(jobs[i].in,in,offset,1,length);
    polxvec_init_subvec2(jobs[i].scalar,scalar,0,1,1);
    offset+=length;
  }
  for(size_t i=1;i<count;i++) {
    if(!pthread_create(&threads[i],NULL,quil_mul_add_refresh_execute,&jobs[i]))started[i]=1;
    else quil_mul_add_refresh_execute(&jobs[i]);
  }
  quil_mul_add_refresh_execute(&jobs[0]);
  for(size_t i=1;i<count;i++)
    if(started[i] && pthread_join(threads[i],NULL))abort();
}
#endif
