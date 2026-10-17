#ifndef TIMING_H
#define TIMING_H

#ifdef TIMING
#ifndef TIMING_DEPTH
#define TIMING_DEPTH 10
#endif
#endif

#include <time.h>

typedef struct _timing{
  double start;
  double end;
  const char *msg;
} timing;

void timing_start(timing *t, const char *msg);
void timing_end(timing *t);
void timing_print(timing *t, size_t depth);

void timing_buffer_init(void);
void timing_buffer_flush(void);

#endif