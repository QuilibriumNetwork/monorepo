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
typedef struct BufferIO_t* BufferIO_ptr;
typedef struct FerretCOT_t* FerretCOT_ptr;
typedef struct FerretCOT_Buffer_t* FerretCOT_Buffer_ptr;
typedef struct block_t* block_ptr;

// Constants
#define ALICE_PARTY 1
#define BOB_PARTY 2

// NetIO functions (TCP-based, original interface)
NetIO_ptr create_netio(int party, const char* address, int port);
void free_netio(NetIO_ptr io);

// BufferIO functions (message-based, new interface)
BufferIO_ptr create_buffer_io(int64_t initial_cap);
void free_buffer_io(BufferIO_ptr io);

// Fill receive buffer with data from external transport
// Returns 0 on success, -1 on error
int buffer_io_fill_recv(BufferIO_ptr io, const uint8_t* data, size_t len);

// Drain send buffer to external transport
// Returns number of bytes copied, or 0 if empty
// Caller provides buffer and max length
size_t buffer_io_drain_send(BufferIO_ptr io, uint8_t* out_buffer, size_t max_len);

// Get current send buffer size (to check if there's data to send)
size_t buffer_io_send_size(BufferIO_ptr io);

// Get current receive buffer available data
size_t buffer_io_recv_available(BufferIO_ptr io);

// Set timeout for blocking receive (milliseconds)
void buffer_io_set_timeout(BufferIO_ptr io, int64_t timeout_ms);

// Set error state (will cause recv to fail)
void buffer_io_set_error(BufferIO_ptr io, const char* message);

// Clear all buffers
void buffer_io_clear(BufferIO_ptr io);

// FerretCOT functions (TCP-based, original interface)
FerretCOT_ptr create_ferret_cot(int party, int threads, NetIO_ptr io, bool malicious);
void free_ferret_cot(FerretCOT_ptr ot);

// FerretCOT functions (Buffer-based, new interface)
// NOTE: create_ferret_cot_buffer does NOT run setup automatically.
// You must call setup_ferret_cot_buffer after both parties have their
// message transport active (i.e., can send/receive data).
FerretCOT_Buffer_ptr create_ferret_cot_buffer(int party, int threads, BufferIO_ptr io, bool malicious);
void free_ferret_cot_buffer(FerretCOT_Buffer_ptr ot);

// Run the OT setup protocol. Must be called after create_ferret_cot_buffer
// when both parties have their BufferIO connected (message transport active).
// For ALICE: generates Delta and runs sender setup
// For BOB: runs receiver setup
// Returns 0 on success, -1 on error (exception caught)
int setup_ferret_cot_buffer(FerretCOT_Buffer_ptr ot, int party);

// Get the Delta correlation value
block_ptr get_delta(FerretCOT_ptr ot);
block_ptr get_delta_buffer(FerretCOT_Buffer_ptr ot);

// Allocate and free blocks
block_ptr allocate_blocks(size_t length);
void free_blocks(block_ptr blocks);

// OT Operations (TCP-based)
void send_cot(FerretCOT_ptr ot, block_ptr b0, size_t length);
void recv_cot(FerretCOT_ptr ot, block_ptr br, bool* choices, size_t length);
void send_rot(FerretCOT_ptr ot, block_ptr b0, block_ptr b1, size_t length);
void recv_rot(FerretCOT_ptr ot, block_ptr br, bool* choices, size_t length);

// OT Operations (Buffer-based)
// All return 0 on success, -1 on error (exception caught)
int send_cot_buffer(FerretCOT_Buffer_ptr ot, block_ptr b0, size_t length);
int recv_cot_buffer(FerretCOT_Buffer_ptr ot, block_ptr br, bool* choices, size_t length);
int send_rot_buffer(FerretCOT_Buffer_ptr ot, block_ptr b0, block_ptr b1, size_t length);
int recv_rot_buffer(FerretCOT_Buffer_ptr ot, block_ptr br, bool* choices, size_t length);

// Block data accessors
size_t get_block_data(block_ptr blocks, size_t index, uint8_t* buffer, size_t buffer_len);
void set_block_data(block_ptr blocks, size_t index, const uint8_t* data, size_t data_len);

// =============================================================================
// State serialization functions (for persistent storage)
// =============================================================================

// Get the size needed to store the FerretCOT state
// This allows storing setup data externally instead of in files
int64_t ferret_cot_state_size(FerretCOT_ptr ot);
int64_t ferret_cot_buffer_state_size(FerretCOT_Buffer_ptr ot);

// Serialize FerretCOT state to a buffer
// buffer must be at least ferret_cot_state_size() bytes
// Returns 0 on success, -1 on error
int ferret_cot_assemble_state(FerretCOT_ptr ot, uint8_t* buffer, int64_t buffer_size);
int ferret_cot_buffer_assemble_state(FerretCOT_Buffer_ptr ot, uint8_t* buffer, int64_t buffer_size);

// Restore FerretCOT state from a buffer (created by assemble_state)
// This must be called INSTEAD of setup, not after
// Returns 0 on success, -1 on error (e.g., parameter mismatch)
int ferret_cot_disassemble_state(FerretCOT_ptr ot, const uint8_t* buffer, int64_t buffer_size);
int ferret_cot_buffer_disassemble_state(FerretCOT_Buffer_ptr ot, const uint8_t* buffer, int64_t buffer_size);

// Check if setup has been run (state is initialized)
bool ferret_cot_is_setup(FerretCOT_ptr ot);
bool ferret_cot_buffer_is_setup(FerretCOT_Buffer_ptr ot);

#ifdef __cplusplus
}
#endif

#endif // EMP_BRIDGE_H