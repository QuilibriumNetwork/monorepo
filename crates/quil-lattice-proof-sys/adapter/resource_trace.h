#ifndef QUIL_NATIVE_RESOURCE_TRACE_H
#define QUIL_NATIVE_RESOURCE_TRACE_H

/* Opt-in diagnostics for controlled native proof runs. Only public phase names
 * and process resource counters are emitted; no witness or transcript data.
 * ru_maxrss is a process high-water mark, not a phase-specific allocation count.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

/* Per-call timestamps let parallel workers report their own phase durations;
 * interleaved begin/end lines alone cannot reliably pair different workers. */
static inline double quil_resource_monotonic_seconds(void) {
  struct timespec now;
  if(clock_gettime(CLOCK_MONOTONIC,&now))return 0;
  return (double)now.tv_sec+(double)now.tv_nsec/1000000000.0;
}

static inline void quil_resource_trace(const char *phase) {
  const char *enabled = getenv("QUIL_NATIVE_RESOURCE_TRACE");
  if (!enabled || strcmp(enabled, "1")) return;
  struct rusage usage;
  struct timespec now;
  if (getrusage(RUSAGE_SELF, &usage) || clock_gettime(CLOCK_MONOTONIC, &now)) return;
#ifdef __APPLE__
  unsigned long long peak_bytes = (unsigned long long)usage.ru_maxrss;
#else
  unsigned long long peak_bytes = (unsigned long long)usage.ru_maxrss * 1024ULL;
#endif
  fprintf(stderr, "quil_native_resource phase=%s monotonic_seconds=%lld.%03ld peak_rss_bytes=%llu user_seconds=%lld.%06ld\n",
          phase, (long long)now.tv_sec, now.tv_nsec / 1000000,
          peak_bytes, (long long)usage.ru_utime.tv_sec, (long)usage.ru_utime.tv_usec);
  fflush(stderr);
}
#endif
