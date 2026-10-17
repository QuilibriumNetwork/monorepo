#ifndef LABRADOR_TAIL_H
#define LABRADOR_TAIL_H

#include "proofsystem.h"
#include "labrador_core.h"

void ldr_tail_prove(lab_proof pi, statement ost, witness owt, 
                    const statement ist, const witness iwt, 
                    const lab_params pp);
int ldr_tail_reduce(statement ost, const statement ist, const lab_proof pi, 
                    const lab_params pp);

#endif
