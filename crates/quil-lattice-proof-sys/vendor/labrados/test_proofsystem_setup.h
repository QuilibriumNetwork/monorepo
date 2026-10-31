#ifndef TEST_PROOFSYSTEM_SETUP_H
#define TEST_PROOFSYSTEM_SETUP_H

#include "polx.h"
#include "proofsystem.h"

void ps_witness_set(witness iwt, polxvec sxl, polxvec **sxq, size_t *nn,
                     size_t *iwtbytes, size_t len, const uint8_t seed[SEEDLEN],
                     uint64_t *nonce);

void ps_statement_set(statement ist, const witness iwt, const polxvec sxl,
                       const polxvec *sxq, size_t nn, size_t nconst,
                       const uint8_t seed[SEEDLEN], uint64_t *nonce);

#endif