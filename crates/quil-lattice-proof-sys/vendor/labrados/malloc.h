#ifndef MALLOC_H
#define MALLOC_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void *_malloc(size_t size) {
  void *ret;
  ret = malloc(size);
  if(ret == NULL) {
    fprintf(stderr,"ERROR: Not enough memory\n");
    exit(1);
  }
  return ret;
}

static void *_aligned_alloc(size_t alignment, size_t size) {
  void *ret;
  ret = aligned_alloc(alignment,size);
  if(ret == NULL) {
    fprintf(stderr,"ERROR: Not enough memory\n");
    exit(1);
  }
  return ret;
}

static void *_aligned_calloc(size_t alignment, size_t size) {
  void *ret;
  ret = aligned_alloc(alignment,size);
  if(ret == NULL) {
    fprintf(stderr,"ERROR: Not enough memory\n");
    exit(1);
  }
  memset(ret,0,size);
  return ret;
}

static void *_realloc(void *ptr, size_t size) {
  void *ret;
  ret = realloc(ptr, size);
  if(ret == NULL) {
    fprintf(stderr,"ERROR: Not enough memory\n");
    exit(1);
  }
  return ret;
}

#endif
