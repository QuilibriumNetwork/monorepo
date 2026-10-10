#ifndef QUIL_PRG_STREAM_H
#define QUIL_PRG_STREAM_H
#include "aesctr.h"

/* Shared sampler byte interface: changing the private PRG does not duplicate
 * or change the Gaussian/uniform sampling algorithms or public AES-128 streams.
 */
#define QUIL_PRG_BLOCKBYTES 512
_Static_assert(AES128CTR_BLOCKBYTES == QUIL_PRG_BLOCKBYTES, "AES-128 stream block size");
_Static_assert(AES256CTR_BLOCKBYTES == QUIL_PRG_BLOCKBYTES, "AES-256 stream block size");
typedef struct {
  void *state;
  void (*squeeze)(uint8_t *,size_t,void *);
} quil_prg_stream;
static inline void quil_prg_aes128_squeeze(uint8_t *out,size_t blocks,void *state) {
  aes128ctr_squeezeblocks(out,blocks,(aes128ctr_ctx *)state);
}
static inline void quil_prg_aes256_squeeze(uint8_t *out,size_t blocks,void *state) {
  aes256ctr_squeezeblocks(out,blocks,(aes256ctr_ctx *)state);
}
static inline void quil_prg_squeeze(uint8_t *out,size_t blocks,quil_prg_stream *stream) {
  stream->squeeze(out,blocks,stream->state);
}
/* Clear these owned buffers; does not certify erasure of all sampler temporaries
 * or register copies elsewhere in the native implementation. */
static inline void quil_prg_clear(void *bytes,size_t len) {
  volatile uint8_t *p=bytes;
  while(len--)*p++=0;
}
#endif
