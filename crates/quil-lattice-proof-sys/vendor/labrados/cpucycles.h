#ifndef CPUCYCLES_H
#define CPUCYCLES_H
#include <stdint.h>
#include <time.h>
/* Probe timing is nanoseconds, not CPU cycles. */
static inline uint64_t cpucycles(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec; }
uint64_t cpucycles_overhead(void);
void warmup(void);
#endif
