#ifndef QUIL_LDR_PARALLEL_H
#define QUIL_LDR_PARALLEL_H
#include "zq_parallel.h"
#include "proofsystem.h"
#include "jlproj.h"

/* Normal-round Zq aggregation, one job per lift. The transcript (JL challenge
 * expansion, scalar challenges and the polynomial-challenge seed) is consumed
 * serially in the original order before any worker starts. Each worker reads
 * the shared JL matrices, projection and input statement, expands its own
 * polynomial challenges from the derived seed and runs the unmodified serial
 * collapse, aggregation and refresh on its own output. Outputs and challenge
 * buffers are disjoint; every started thread is joined before they are freed. */
typedef struct {
  struct _sparsecnst *out;
  struct _zqcnstset *input;
  const uint8_t *jlmat1,*jlmat2;
  const int32_t *p;
  int64_t *chalz;            /* 256 JL scalars followed by the Zq scalars */
  struct polxvec_str *chalx; /* length zero without sigma-m1 rows */
  int expand_chalx;
  uint8_t chalx_seed[SEEDLEN];
} quil_ldr_zq_job;
static void *quil_ldr_zq_execute(void *opaque) {
  quil_ldr_zq_job *job=opaque;
  jl_aggregate_mat(job->out->lin->phi[0],job->jlmat1,job->jlmat2,job->chalz);
  int64_t proj=jlproj_collapsproj(job->p,job->chalz);
  polxvec_monomial(job->out->b,0,0,proj);
  if(job->expand_chalx)polxvec_almostuniform(job->chalx,job->chalx_seed,0);
  zqcnstset_aggregate_add(job->out,job->input,&job->chalz[256],job->chalx);
  sparsecnst_refresh(job->out);
  return NULL;
}
/* The original sample_chalx_uniform hash step without its expansion; a missing
 * polynomial group must not advance h. */
static void quil_ldr_zq_prepare_challenge_seed(quil_ldr_zq_job *job,uint8_t h[HASHLEN]) {
  job->expand_chalx=0;
  if(!job->chalx->len)return;
  uint8_t hashbuf[HASHLEN+SEEDLEN];
  shake128(hashbuf,sizeof(hashbuf),h,HASHLEN);
  memcpy(h,hashbuf,HASHLEN);
  memcpy(job->chalx_seed,hashbuf+HASHLEN,SEEDLEN);
  job->expand_chalx=1;
}
static size_t quil_ldr_zq_batch_size(size_t nn) {
  if(nn<256)return 1;
  size_t count=quil_native_thread_limit();
  /* Each worker's JL collapse allocates one nn-length temporary vector. Bound
   * the concurrent temporaries to 256 MiB; oversized single jobs stay serial. */
  size_t budget=256U*1024U*1024U,per_poly=K*sizeof(poly)+sizeof(double);
  if(nn>budget/per_poly)return 1;
  size_t bytes=nn*per_poly;
  while(count>1 && bytes>budget/count)count--;
  return count;
}
static void quil_ldr_zq_execute_batch(quil_ldr_zq_job *jobs,size_t count) {
  pthread_t threads[QUIL_ZQ_MAX_JOBS];
  int started[QUIL_ZQ_MAX_JOBS]={0};
  if(!count || count>QUIL_ZQ_MAX_JOBS)abort();
  for(size_t i=1;i<count;i++) {
    if(!pthread_create(&threads[i],NULL,quil_ldr_zq_execute,&jobs[i]))started[i]=1;
    else quil_ldr_zq_execute(&jobs[i]);
  }
  quil_ldr_zq_execute(&jobs[0]);
  for(size_t i=1;i<count;i++)
    if(started[i] && pthread_join(threads[i],NULL))abort();
}
#endif
