#ifndef EMP_BRIDGE_H
#define EMP_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Opaque pointers to hide C++ implementation
typedef struct NetIO_t* NetIO_ptr;
typedef struct FerretCOT_t* FerretCOT_ptr;
typedef struct block_t* block_ptr;

// Constants
#define ALICE_PARTY 1
#define BOB_PARTY 2

// NetIO functions
NetIO_ptr create_netio(int party, const char* address, int port);
void free_netio(NetIO_ptr io);

// FerretCOT functions
FerretCOT_ptr create_ferret_cot(int party, int threads, NetIO_ptr io, bool malicious);
void free_ferret_cot(FerretCOT_ptr ot);

// Get the Delta correlation value
block_ptr get_delta(FerretCOT_ptr ot);

// Allocate and free blocks
block_ptr allocate_blocks(size_t length);
void free_blocks(block_ptr blocks);

// OT Operations
void send_cot(FerretCOT_ptr ot, block_ptr b0, size_t length);
void recv_cot(FerretCOT_ptr ot, block_ptr br, bool* choices, size_t length);

void send_rot(FerretCOT_ptr ot, block_ptr b0, block_ptr b1, size_t length);
void recv_rot(FerretCOT_ptr ot, block_ptr br, bool* choices, size_t length);

size_t get_block_data(block_ptr blocks, size_t index, uint8_t* buffer, size_t buffer_len);
void set_block_data(block_ptr blocks, size_t index, const uint8_t* data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif // EMP_BRIDGE_H