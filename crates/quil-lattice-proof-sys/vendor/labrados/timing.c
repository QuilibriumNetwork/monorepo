#include <time.h>
#include "timing.h"
#include "stdio.h"

#if defined(TIMING) && defined(TIMING_WALL)
#include <omp.h>
#endif

#define INDENT "|----"

#ifdef TIMING
static char timing_buf[256 * 1024];
#endif

void timing_start(timing *t, const char *msg){
  #if defined(TIMING) && defined(TIMING_WALL)
  t->start = omp_get_wtime();
  t->msg = msg;
  #elif defined(TIMING)
  t->start = (double)clock();
  t->msg = msg;
  #else
  (void)t;
  (void)msg;
  #endif
}

void timing_end(timing *t){
  #if defined(TIMING) && defined(TIMING_WALL)
  t->end = omp_get_wtime();
  #elif defined(TIMING)
  t->end = (double)clock();
  #else
  (void)t;
  #endif
}

void timing_print(timing *t, size_t depth){
  #ifdef TIMING
  size_t i;
  double time = t->end - t->start;
  double elapsed;
  
  #ifdef TIMING_WALL
  elapsed = time * 1000;
  #else
  elapsed = time/CLOCKS_PER_SEC * 1000;
  #endif

  if(depth > TIMING_DEPTH){
    return;
  }
  for(i=0;i<depth;i++){
    printf(INDENT);
  }
  printf("%s: %.0fms", t->msg, elapsed);
  
  if(elapsed > 1000){
    printf(" (%.2fs)", elapsed/1000);
  }
  printf("\n");
  #else
  (void)t;
  (void)depth;
  #endif
}

void timing_buffer_init(void){
  #ifdef TIMING
    fflush(stdout);
    setvbuf(stdout, timing_buf, _IOFBF, sizeof(timing_buf));
  #endif
}

void timing_buffer_flush(void){
  #ifdef TIMING
    fflush(stdout);
  #endif
}

