#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define FIPS202_NAMESPACE(s) pqcrystals_dilithium_fips202_ref_##s

typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_ctx;

#define KeccakF_RoundConstants FIPS202_NAMESPACE(KeccakF_RoundConstants)
extern const uint64_t KeccakF_RoundConstants[];

typedef keccak_ctx shake128incctx;
#define shake128_inc_init FIPS202_NAMESPACE(shake128_inc_init)
#define shake128_inc_ctx_reset(CTX) shake128_inc_init(CTX)
#define shake128_inc_ctx_release(CTX)
void shake128_inc_init(shake128incctx *ctx);
#define shake128_inc_absorb FIPS202_NAMESPACE(shake128_inc_absorb)
void shake128_inc_absorb(shake128incctx *ctx, const uint8_t *in, size_t inlen);
#define shake128_inc_finalize FIPS202_NAMESPACE(shake128_inc_finalize)
void shake128_inc_finalize(shake128incctx *ctx);
#define shake128_inc_squeeze FIPS202_NAMESPACE(shake128_inc_squeeze)
void shake128_inc_squeeze(uint8_t *out, size_t outlen, shake128incctx *ctx);
#define shake128_inc_absorb_once FIPS202_NAMESPACE(shake128_inc_absorb_once)
void shake128_inc_absorb_once(shake128incctx *ctx, const uint8_t *in, size_t inlen);
#define shake128_inc_squeezeblocks FIPS202_NAMESPACE(shake128_inc_squeezeblocks)
void shake128_inc_squeezeblocks(uint8_t *out, size_t nblocks, shake128incctx *ctx);

typedef keccak_ctx shake256incctx;
#define shake256_inc_init FIPS202_NAMESPACE(shake256_inc_init)
#define shake256_inc_ctx_reset(CTX) shake256_inc_init(CTX)
#define shake256_inc_ctx_release(CTX)
void shake256_inc_init(shake256incctx *ctx);
#define shake256_inc_absorb FIPS202_NAMESPACE(shake256_inc_absorb)
void shake256_inc_absorb(shake256incctx *ctx, const uint8_t *in, size_t inlen);
#define shake256_inc_finalize FIPS202_NAMESPACE(shake256_inc_finalize)
void shake256_inc_finalize(shake256incctx *ctx);
#define shake256_inc_squeeze FIPS202_NAMESPACE(shake256_inc_squeeze)
void shake256_inc_squeeze(uint8_t *out, size_t outlen, shake256incctx *ctx);
#define shake256_inc_absorb_once FIPS202_NAMESPACE(shake256_inc_absorb_once)
void shake256_inc_absorb_once(shake256incctx *ctx, const uint8_t *in, size_t inlen);
#define shake256_inc_squeezeblocks FIPS202_NAMESPACE(shake256_inc_squeezeblocks)
void shake256_inc_squeezeblocks(uint8_t *out, size_t nblocks,  shake256incctx *ctx);

#define shake128 FIPS202_NAMESPACE(shake128)
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define shake256 FIPS202_NAMESPACE(shake256)
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define sha3_256 FIPS202_NAMESPACE(sha3_256)
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
#define sha3_512 FIPS202_NAMESPACE(sha3_512)
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);

#endif
