#ifndef LABRADOODLE_H
#define LABRADOODLE_H

#include <stdint.h>
#include "proofsystem.h"
#include "labrador_core.h"

void ldd_aggregate_jl(sparsecnst *cnst, size_t r, size_t n[r],
                      size_t projbits[r], const uint8_t *jlmat1, 
                      const uint8_t *jlmat2, const int64_t chalz[256]);
void ldd_prove(lab_proof pi, statement ost, witness owt, const statement ist, 
             const witness iwt, const lab_params pp);
void ldd_reduce(statement ost, const statement ist, const lab_proof pi,
                const lab_params pp);


#endif