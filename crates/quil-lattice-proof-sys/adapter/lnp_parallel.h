#ifndef QUIL_LNP_PARALLEL_H
#define QUIL_LNP_PARALLEL_H
#include "zq_parallel.h"
#include "proofsystem.h"

/* LNP-round JL collapses. Every challenge has already been sampled from the
 * transcript in the original order; workers only read the shared matrices and
 * their own challenge, and write disjoint owning outputs with the unmodified
 * serial kernel. Started threads are joined before any output is read. */
typedef struct {
  struct polxvec_str *out;
  const uint8_t *jlmat1,*jlmat2;
  const int64_t *chalz;
} quil_jl_mat_job;
static void *quil_jl_mat_execute(void *opaque) {
  quil_jl_mat_job *job=opaque;
  jl_aggregate_mat(job->out,job->jlmat1,job->jlmat2,job->chalz);
  return NULL;
}
static void quil_jl_mat_execute_all(quil_jl_mat_job *jobs,size_t total) {
  size_t limit=quil_native_thread_limit();
  for(size_t base=0;base<total;base+=limit) {
    size_t count=MIN(limit,total-base);
    pthread_t threads[QUIL_ZQ_MAX_JOBS];
    int started[QUIL_ZQ_MAX_JOBS]={0};
    if(!count || count>QUIL_ZQ_MAX_JOBS)abort();
    for(size_t i=1;i<count;i++) {
      if(!pthread_create(&threads[i],NULL,quil_jl_mat_execute,&jobs[base+i]))started[i]=1;
      else quil_jl_mat_execute(&jobs[base+i]);
    }
    quil_jl_mat_execute(&jobs[base]);
    for(size_t i=1;i<count;i++)
      if(started[i] && pthread_join(threads[i],NULL))abort();
  }
}
#endif
