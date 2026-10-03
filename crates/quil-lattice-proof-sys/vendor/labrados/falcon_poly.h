#ifndef FALCON_POLY_H
#define FALCON_POLY_H

#include <stdint.h>
#include "falcon.h"
#include "poly.h"
#include "data.h"

#define FALCON_N 512
#define FALCON_LOGN 9
#define FALCON_BETA 34034726
#define FALCON_PKLEN 897
#define FALCON_SKLEN 1281
#define FALCON_TMPKGLEN 15879

extern const pdata_ptr falcon_prime;

void falcon_keygen(uint8_t sk[FALCON_SKLEN], uint8_t pk[FALCON_PKLEN]);
void falcon_preimage_sample(poly s1[FALCON_N/N], poly s2[FALCON_N/N], const poly t[FALCON_N/N], const uint8_t sk[FALCON_SKLEN]);
void falcon_decode_pubkey(poly h[FALCON_N/N], const uint8_t pk[FALCON_PKLEN]);

#endif
