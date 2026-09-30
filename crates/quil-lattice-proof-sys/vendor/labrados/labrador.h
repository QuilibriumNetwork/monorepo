#ifndef LABRADOR_H
#define LABRADOR_H

#include <stdint.h>
#include <stddef.h>
#include "polz.h"
#include "proofsystem.h"
#include "labrador_core.h"

void ldr_aggregate_zq(sparsecnst zqagg[LIFTS], const statement ist, 
                      const uint8_t *jlmat1, const uint8_t *jlmat2, 
                      const int32_t p[256], size_t nn, size_t r_old, 
                      uint8_t h[HASHLEN]);
void ldr_aggregate_rq(sparsecnst finalcnst, const statement ist, 
                      const sparsecnst zqagg[LIFTS], size_t nn,  size_t r_old, 
                      uint8_t h[HASHLEN]);                      

void ldr_prove(lab_proof pi, statement ost, witness owt, const statement ist,
               const witness iwt, const lab_params pp);
int ldr_reduce(statement ost, const statement ist, const lab_proof pi,
               const lab_params pp);


#endif
