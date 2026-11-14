#ifndef QUIL_FIXTURE_COEFFICIENT_POOL_H
#define QUIL_FIXTURE_COEFFICIENT_POOL_H

/* The submitted input statement is read-only during checking/proving/reduction.
 * Share PUBLIC coefficient polynomials inside that statement, with bounded
 * storage and lookup work for coefficients outside the common fixed set.
 * Standalone transforms retain deep copies. Combined Dachshund/Pack calls may
 * hold read-only views until their input statement is released. Pool borrowers
 * keep normal vector dimensions and must be detached before statement_free;
 * the pool owns and releases each shared allocation exactly once.
 */
#define FIXTURE_POOL_SLOTS (2*N+3)
#define FIXTURE_POOL_MAX_BORROWERS (1U<<22)
#define FIXTURE_POOL_GENERAL_VALUES 16384
#define FIXTURE_POOL_GENERAL_BUCKETS 32768
#define FIXTURE_POOL_MAX_PROBES 32
typedef struct {
  uint64_t hash;
  int64_t coefficients[N];
  struct polxvec_str value;
} fixture_general_coefficient;
typedef struct {
  struct polxvec_str values[FIXTURE_POOL_SLOTS];
  struct polxvec_str **borrowers;
  size_t count, capacity;
  fixture_general_coefficient *general;
  uint32_t *buckets;
  size_t general_count, conversion_hits;
  // Hints exist only between one frontend submission and its row sharing.
  struct { struct polxvec_str *out, *source; } submitted_copies[8];
  size_t submitted_copy_count;
} fixture_coefficient_pool;

static size_t fixture_coefficient_slot(const int64_t *a) {
  size_t nonzero=0;
  int all_one=1,all_minus_one=1;
  // Keep this fixed-length reduction free of index tracking and branches so
  // the compiler can compare several public coefficients in parallel.
  for(size_t i=0;i<N;i++) {
    nonzero+=(a[i]!=0);
    all_one&=(a[i]==1);
    all_minus_one&=(a[i]==-1);
  }
  if(!nonzero)return 0;
  if(nonzero==1) {
    size_t index=0;
    while(!a[index])index++;
    if(a[index]==1 || a[index]==-1)return 1+2*index+(a[index]<0);
  }
  if(all_one)return 2*N+1;
  if(all_minus_one)return 2*N+2;
  return FIXTURE_POOL_SLOTS;
}

static int fixture_pool_same(const polxvec a,const polxvec b) {
  if(a->widths[0]!=b->widths[0])return 0;
  for(size_t k=0;k<K;k++)
    if(memcmp(a->proj[k][0],b->proj[k][0],sizeof(poly)))return 0;
  return 1;
}

static uint64_t fixture_coefficient_hash(const int64_t *a) {
  uint64_t hash=UINT64_C(14695981039346656037);
  for(size_t i=0;i<N;i++){hash^=(uint64_t)a[i];hash*=UINT64_C(1099511628211);}
  return hash;
}

/* Read-only lookup precedes conversion. Raw equality, not hash equality or
 * modular equivalence, authorizes a hit. Copying preserves ordinary ownership;
 * the existing post-submission pool then shares and tracks the allocation. */
static struct polxvec_str *fixture_pool_lookup_cached(fixture_coefficient_pool *pool,
                                                      polxvec out,const int64_t *a) {
  if(out->len!=1 || out->off || out->stride!=1 || out->alloc!=1)return NULL;
  size_t slot=fixture_coefficient_slot(a);
  struct polxvec_str *value=NULL;
  if(slot<FIXTURE_POOL_SLOTS)value=&pool->values[slot];
  else if(pool->general) {
    uint64_t hash=fixture_coefficient_hash(a);
    for(size_t probe=0;probe<FIXTURE_POOL_MAX_PROBES;probe++) {
      size_t bucket=(hash+probe)&(FIXTURE_POOL_GENERAL_BUCKETS-1);
      uint32_t index=pool->buckets[bucket];
      if(!index)break;
      fixture_general_coefficient *entry=&pool->general[index-1];
      if(entry->hash==hash && !memcmp(entry->coefficients,a,sizeof(entry->coefficients))) {
        value=&entry->value;break;
      }
    }
  }
  return value && value->alloc ? value : NULL;
}
static int fixture_pool_copy_cached(void *opaque,polxvec out,const int64_t *a) {
  fixture_coefficient_pool *pool=opaque;
  struct polxvec_str *value=fixture_pool_lookup_cached(pool,out,a);
  if(!value)return 0;
  polxvec_copy(out,value);
  pool->conversion_hits++;
  return 1;
}

/* Only the linear frontend uses this callback. After the exact owning copy it
 * changes widths, but never coefficient values, before fixture_share_row.
 * Standalone conversion callers retain the ordinary callback above. */
static int fixture_pool_copy_submitted(void *opaque,polxvec out,const int64_t *a) {
  fixture_coefficient_pool *pool=opaque;
  struct polxvec_str *value=fixture_pool_lookup_cached(pool,out,a);
  if(!value)return 0;
  polxvec_copy(out,value);
  pool->conversion_hits++;
  if(pool->submitted_copy_count<8) {
    size_t slot=pool->submitted_copy_count++;
    pool->submitted_copies[slot].out=out;
    pool->submitted_copies[slot].source=value;
  }
  return 1;
}

static struct polxvec_str *fixture_pool_general(fixture_coefficient_pool *pool,
                                               const polxvec value,const int64_t *a) {
  if(!pool->general) {
    fixture_general_coefficient *values=calloc(FIXTURE_POOL_GENERAL_VALUES,sizeof(*values));
    uint32_t *buckets=calloc(FIXTURE_POOL_GENERAL_BUCKETS,sizeof(*buckets));
    if(!values || !buckets){free(values);free(buckets);return NULL;}
    pool->general=values;pool->buckets=buckets;
  }
  // This hash is only a bounded lookup index, never an equality/security check.
  uint64_t hash=fixture_coefficient_hash(a);
  for(size_t probe=0;probe<FIXTURE_POOL_MAX_PROBES;probe++) {
    size_t bucket=(hash+probe)&(FIXTURE_POOL_GENERAL_BUCKETS-1);
    uint32_t index=pool->buckets[bucket];
    if(index) {
      fixture_general_coefficient *entry=&pool->general[index-1];
      if(entry->hash==hash && !memcmp(entry->coefficients,a,sizeof(entry->coefficients))
         && fixture_pool_same(&entry->value,value))return &entry->value;
    } else {
      if(pool->general_count==FIXTURE_POOL_GENERAL_VALUES)return NULL;
      fixture_general_coefficient *entry=&pool->general[pool->general_count++];
      entry->hash=hash;pool->buckets[bucket]=(uint32_t)pool->general_count;
      memcpy(entry->coefficients,a,sizeof(entry->coefficients));
      return &entry->value;
    }
  }
  // A crowded probe chain preserves the ordinary owning allocation.
  return NULL;
}

static void fixture_pool_share(fixture_coefficient_pool *pool,polxvec value,const int64_t *a) {
  if(value->len!=1 || value->off || value->stride!=1
     || value->alloc!=1 || !value->widths || pool->count==FIXTURE_POOL_MAX_BORROWERS)return;
  if(pool->count==pool->capacity) {
    size_t capacity=pool->capacity ? pool->capacity*2 : 128;
    void *grown=realloc(pool->borrowers,capacity*sizeof(*pool->borrowers));
    // If the bookkeeping cannot grow, retain the normal owning vector.
    if(!grown)return;
    pool->borrowers=grown;pool->capacity=capacity;
  }
  struct polxvec_str *shared=NULL;
  for(size_t i=0;i<pool->submitted_copy_count;i++) {
    if(pool->submitted_copies[i].out==value) {
      struct polxvec_str *source=pool->submitted_copies[i].source;
      // The frontend may have reset widths after the exact copy.
      if(source->alloc && source->widths[0]==value->widths[0])shared=source;
      pool->submitted_copies[i].out=NULL;
      break;
    }
  }
  if(!shared) {
    size_t slot=fixture_coefficient_slot(a);
    shared=slot==FIXTURE_POOL_SLOTS
        ? fixture_pool_general(pool,value,a) : &pool->values[slot];
    if(!shared)return;
    // General/hash hits still require exact native representation equality.
    if(shared->alloc && !fixture_pool_same(value,shared))return;
  }
  if(shared->alloc) {
    polxvec_free(value);
    *value=*shared;
  } else {
    *shared=*value;
  }
  pool->borrowers[pool->count++]=value;
}

static void fixture_pool_detach(fixture_coefficient_pool *pool) {
  for(size_t i=0;i<pool->count;i++)pool->borrowers[i]->alloc=0;
}
static void fixture_pool_free(fixture_coefficient_pool *pool) {
  for(size_t i=0;i<FIXTURE_POOL_SLOTS;i++)polxvec_free(&pool->values[i]);
  for(size_t i=0;i<pool->general_count;i++)polxvec_free(&pool->general[i].value);
  free(pool->general);free(pool->buckets);
  free(pool->borrowers);
}
#endif
