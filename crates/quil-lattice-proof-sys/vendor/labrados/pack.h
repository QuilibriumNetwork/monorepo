#ifndef PACK_H
#define PACK_H

#include <stdint.h>
#include <stddef.h>
#include "proofsystem.h"
#include "labrador_core.h"
#include "lnp.h"

typedef struct{
  size_t np;
  lab_proof *p;
  lnp_proof *zkp; // NULL iff no zero-knowledge
  witness owt;
} pack_proof[1];

typedef struct{
  size_t np;
  lab_params *p;
  lnp_params *zkp; // NULL iff no zero-knowledge
  size_t zkround; // run zkp proof after zkround rounds
} pack_params[1];

void pack_proof_init(pack_proof pi, const pack_params pp);
void pack_proof_free(pack_proof pi);

void pack_params_gen(pack_params pp, size_t *pibits, const statement st, int zk, 
                     size_t iwtbits);
void pack_params_print(const pack_params pp);
void pack_params_free(pack_params pp);

/* Returns 0 on success; nonzero aborts proving without a usable proof. */
int pack_prove(pack_proof pi, const statement ist, const witness iwt,
                const pack_params pp);
int pack_verify(const statement ist, const pack_params pp, 
                const pack_proof pi);

#endif
