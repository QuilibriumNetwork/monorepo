#ifndef ORT_PACK_H
#define ORT_PACK_H

#include <stdint.h>
#include <stddef.h>
#include "pack.h"
#include "orthus.h"
#include "poly.h"
#include "polz.h"

typedef struct{
  ort_proof pi_ort;
  pack_proof pi_pack;
} ort_pack_proof[1];

typedef struct{
  ort_params pp_ort;
  pack_params pp_pack;
} ort_pack_params[1];

void ort_pack_proof_init(ort_pack_proof pi, const ort_pack_params pp);
void ort_pack_proof_free(ort_pack_proof pi);

int ort_pack_params_gen(ort_pack_params pp, size_t *pibits, 
                         const ort_statement st, int zk);
void ort_pack_params_print(const ort_pack_params pp);
void ort_pack_params_free(ort_pack_params pp);

void ort_pack_preprocess(polz **outcom_ptr, poly **midcom_ptr, poly **incom_ptr,
                         const ort_statement st, const ort_block *block, 
                         const ort_pack_params pp);
void ort_pack_prove(ort_pack_proof pi, const polz *outcom, const poly *midcom, 
                    const poly *incom, const ort_statement ist, 
                    const ort_witness iwt, const ort_pack_params pp);
int ort_pack_verify(const polz *outcom, const ort_statement ist, 
                    const ort_pack_params pp, const ort_pack_proof pi);

#endif
