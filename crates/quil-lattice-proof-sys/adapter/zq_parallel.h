#ifndef QUIL_ZQ_PARALLEL_H
#define QUIL_ZQ_PARALLEL_H
#include <pthread.h>
#include <unistd.h>
#include "constraints.h"
#include "fips202.h"

/* Jobs have disjoint owning outputs/challenge buffers and a read-only shared
 * input statement. Transcript updates and seed derivation stay serial. Workers
 * may expand an already-derived public seed into their own challenge buffer;
 * no transcript mutation or commitment-key growth occurs in a worker. Every
 * started thread is joined before buffers are freed. */
#define QUIL_ZQ_MAX_JOBS 8
typedef struct {
  struct _sparsecnst *out;
  struct _zqcnstset *input;
  int64_t *chalz;
  struct polxvec_str *chalx;
  int expand_chalx;
  uint8_t chalx_seed[SEEDLEN];
} quil_zq_job;
/* The original sample_chalx_uniform hash step, separated from its expensive
 * deterministic expansion. A missing polynomial group must not advance h. */
static void quil_zq_prepare_challenge_seed(quil_zq_job *job,uint8_t h[HASHLEN]) {
  job->expand_chalx=0;
  if(!job->chalx->len)return;
  uint8_t hashbuf[HASHLEN+SEEDLEN];
  shake128(hashbuf,sizeof(hashbuf),h,HASHLEN);
  memcpy(h,hashbuf,HASHLEN);
  memcpy(job->chalx_seed,hashbuf+HASHLEN,SEEDLEN);
  job->expand_chalx=1;
}
static void *quil_zq_expand_challenges(void *opaque) {
  quil_zq_job *job=opaque;
  if(job->expand_chalx)polxvec_almostuniform(job->chalx,job->chalx_seed,0);
  return NULL;
}
static void *quil_zq_execute(void *opaque) {
  quil_zq_job *job=opaque;
  quil_zq_expand_challenges(job);
  quil_zqcnstset_aggregate_refreshed(job->out,job->input,job->chalz,job->chalx);
  return NULL;
}
static void quil_zq_execute_batch(quil_zq_job *jobs,size_t count) {
  pthread_t threads[QUIL_ZQ_MAX_JOBS];
  int started[QUIL_ZQ_MAX_JOBS]={0};
  if(!count || count>QUIL_ZQ_MAX_JOBS)abort();
  for(size_t i=1;i<count;i++) {
    if(!pthread_create(&threads[i],NULL,quil_zq_execute,&jobs[i]))started[i]=1;
    else quil_zq_execute(&jobs[i]);
  }
  quil_zq_execute(&jobs[0]);
  for(size_t i=1;i<count;i++)
    if(started[i] && pthread_join(threads[i],NULL))abort();
}
static size_t quil_native_thread_limit(void) {
  long cpus=sysconf(_SC_NPROCESSORS_ONLN);
  size_t count=cpus>1 ? (cpus<QUIL_ZQ_MAX_JOBS ? (size_t)cpus : QUIL_ZQ_MAX_JOBS) : 1;
  const char *limit=getenv("QUIL_NATIVE_AGGREGATION_THREADS");
  if(limit) {
    if(strlen(limit)!=1 || limit[0]<'1' || limit[0]>'8')return 1;
    if(count>(size_t)(limit[0]-'0'))count=(size_t)(limit[0]-'0');
  }
  return count;
}
static size_t quil_zq_batch_size(size_t scalar_count,size_t polynomial_count) {
  // A polynomial challenge can carry substantial work even with few scalar rows.
  if(scalar_count<32768 && polynomial_count<256)return 1;
  size_t count=quil_native_thread_limit();
  /* Cap parallel-batch challenge storage at 1536 MiB, including widths.
   * Oversized individual jobs retain the serial fallback.
   * Checked division avoids overflow for general frontend dimensions. */
  size_t budget=1536U*1024U*1024U;
  size_t per_poly=K*sizeof(poly)+sizeof(double);
  if(scalar_count>budget/sizeof(int64_t))return 1;
  size_t bytes=scalar_count*sizeof(int64_t);
  if(polynomial_count>(budget-bytes)/per_poly)return 1;
  bytes+=polynomial_count*per_poly;
  while(count>1 && bytes>budget/count)count--;
  return count;
}
#endif
