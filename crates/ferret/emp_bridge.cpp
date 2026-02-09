#include "emp_bridge.h"
#include <emp-tool/emp-tool.h>
#include <emp-tool/io/buffer_io_channel.h>
#include <emp-ot/emp-ot.h>
#include <cstring>

using namespace emp;

struct NetIO_t {
    NetIO* netio;
};

struct BufferIO_t {
    BufferIO* bufferio;
};

struct FerretCOT_t {
    FerretCOT<NetIO>* ferret_cot;
};

struct FerretCOT_Buffer_t {
    FerretCOT<BufferIO>* ferret_cot;
};

struct block_t {
    block* blocks;
};

// =============================================================================
// NetIO functions (TCP-based, original interface)
// =============================================================================

NetIO_ptr create_netio(int party, const char* address, int port) {
    NetIO_ptr io_ptr = new NetIO_t();
    if (party == ALICE_PARTY) {
        io_ptr->netio = new NetIO(nullptr, port);
    } else {
        io_ptr->netio = new NetIO(address, port);
    }
    return io_ptr;
}

void free_netio(NetIO_ptr io) {
    if (io) {
        delete io->netio;
        delete io;
    }
}

// =============================================================================
// BufferIO functions (message-based, new interface)
// =============================================================================

BufferIO_ptr create_buffer_io(int64_t initial_cap) {
    BufferIO_ptr io_ptr = new BufferIO_t();
    io_ptr->bufferio = new BufferIO(initial_cap);
    return io_ptr;
}

void free_buffer_io(BufferIO_ptr io) {
    if (io) {
        delete io->bufferio;
        delete io;
    }
}

int buffer_io_fill_recv(BufferIO_ptr io, const uint8_t* data, size_t len) {
    if (!io || !io->bufferio || !data) return -1;
    try {
        io->bufferio->fill_recv_buffer(reinterpret_cast<const char*>(data), len);
        return 0;
    } catch (...) {
        return -1;
    }
}

size_t buffer_io_drain_send(BufferIO_ptr io, uint8_t* out_buffer, size_t max_len) {
    if (!io || !io->bufferio || !out_buffer) return 0;
    return io->bufferio->drain_send_buffer(reinterpret_cast<char*>(out_buffer), max_len);
}

size_t buffer_io_send_size(BufferIO_ptr io) {
    if (!io || !io->bufferio) return 0;
    return io->bufferio->send_buffer_size();
}

size_t buffer_io_recv_available(BufferIO_ptr io) {
    if (!io || !io->bufferio) return 0;
    return io->bufferio->recv_buffer_available();
}

void buffer_io_set_timeout(BufferIO_ptr io, int64_t timeout_ms) {
    if (io && io->bufferio) {
        io->bufferio->set_recv_timeout(timeout_ms);
    }
}

void buffer_io_set_error(BufferIO_ptr io, const char* message) {
    if (io && io->bufferio && message) {
        io->bufferio->set_error(std::string(message));
    }
}

void buffer_io_clear(BufferIO_ptr io) {
    if (io && io->bufferio) {
        io->bufferio->clear();
    }
}

// =============================================================================
// FerretCOT functions (TCP-based, original interface)
// =============================================================================

FerretCOT_ptr create_ferret_cot(int party, int threads, NetIO_ptr io, bool malicious) {
    FerretCOT_ptr ot_ptr = new FerretCOT_t();
    ot_ptr->ferret_cot = new FerretCOT<NetIO>(party, threads, &io->netio, malicious, true);
    return ot_ptr;
}

void free_ferret_cot(FerretCOT_ptr ot) {
    if (ot) {
        delete ot->ferret_cot;
        delete ot;
    }
}

block_ptr get_delta(FerretCOT_ptr ot) {
    block_ptr delta_ptr = new block_t();
    delta_ptr->blocks = new block[1];
    delta_ptr->blocks[0] = ot->ferret_cot->Delta;
    return delta_ptr;
}

void send_cot(FerretCOT_ptr ot, block_ptr b0, size_t length) {
    ot->ferret_cot->send_cot(b0->blocks, length);
}

void recv_cot(FerretCOT_ptr ot, block_ptr br, bool* choices, size_t length) {
    ot->ferret_cot->recv_cot(br->blocks, choices, length);
}

void send_rot(FerretCOT_ptr ot, block_ptr b0, block_ptr b1, size_t length) {
    ot->ferret_cot->send_rot(b0->blocks, b1->blocks, length);
}

void recv_rot(FerretCOT_ptr ot, block_ptr br, bool* choices, size_t length) {
    ot->ferret_cot->recv_rot(br->blocks, choices, length);
}

// =============================================================================
// FerretCOT functions (Buffer-based, new interface)
// =============================================================================

FerretCOT_Buffer_ptr create_ferret_cot_buffer(int party, int threads, BufferIO_ptr io, bool malicious) {
    FerretCOT_Buffer_ptr ot_ptr = new FerretCOT_Buffer_t();
    // IMPORTANT: Pass run_setup=false to avoid blocking I/O during construction.
    // With BufferIO, there's no peer connected yet, so setup() would timeout waiting
    // for data. The caller must ensure setup() is called later when both parties
    // have their message transport active.
    ot_ptr->ferret_cot = new FerretCOT<BufferIO>(party, threads, &io->bufferio, malicious, false);
    return ot_ptr;
}

void free_ferret_cot_buffer(FerretCOT_Buffer_ptr ot) {
    if (ot) {
        delete ot->ferret_cot;
        delete ot;
    }
}

int setup_ferret_cot_buffer(FerretCOT_Buffer_ptr ot, int party) {
    if (!ot || !ot->ferret_cot) return -1;

    try {
        // Run the deferred setup now that message transport is active.
        // This mirrors what would happen in the constructor if run_setup=true.
        if (party == ALICE_PARTY) {
            PRG prg;
            block Delta;
            prg.random_block(&Delta);
            block one = makeBlock(0xFFFFFFFFFFFFFFFFLL, 0xFFFFFFFFFFFFFFFELL);
            Delta = Delta & one;
            Delta = Delta ^ 0x1;
            ot->ferret_cot->setup(Delta);
        } else {
            ot->ferret_cot->setup();
        }
        return 0;
    } catch (const std::exception& e) {
        // Exception during setup - likely timeout or IO error
        return -1;
    } catch (...) {
        // Unknown exception
        return -1;
    }
}

block_ptr get_delta_buffer(FerretCOT_Buffer_ptr ot) {
    block_ptr delta_ptr = new block_t();
    delta_ptr->blocks = new block[1];
    delta_ptr->blocks[0] = ot->ferret_cot->Delta;
    return delta_ptr;
}

int send_cot_buffer(FerretCOT_Buffer_ptr ot, block_ptr b0, size_t length) {
    if (!ot || !ot->ferret_cot || !b0) return -1;
    try {
        ot->ferret_cot->send_cot(b0->blocks, length);
        return 0;
    } catch (...) {
        return -1;
    }
}

int recv_cot_buffer(FerretCOT_Buffer_ptr ot, block_ptr br, bool* choices, size_t length) {
    if (!ot || !ot->ferret_cot || !br) return -1;
    try {
        ot->ferret_cot->recv_cot(br->blocks, choices, length);
        return 0;
    } catch (...) {
        return -1;
    }
}

int send_rot_buffer(FerretCOT_Buffer_ptr ot, block_ptr b0, block_ptr b1, size_t length) {
    if (!ot || !ot->ferret_cot || !b0 || !b1) return -1;
    try {
        ot->ferret_cot->send_rot(b0->blocks, b1->blocks, length);
        return 0;
    } catch (...) {
        return -1;
    }
}

int recv_rot_buffer(FerretCOT_Buffer_ptr ot, block_ptr br, bool* choices, size_t length) {
    if (!ot || !ot->ferret_cot || !br) return -1;
    try {
        ot->ferret_cot->recv_rot(br->blocks, choices, length);
        return 0;
    } catch (...) {
        return -1;
    }
}

// =============================================================================
// Block data accessors
// =============================================================================

block_ptr allocate_blocks(size_t length) {
    block_ptr blocks_ptr = new block_t();
    blocks_ptr->blocks = new block[length];
    return blocks_ptr;
}

void free_blocks(block_ptr blocks) {
    if (blocks) {
        delete[] blocks->blocks;
        delete blocks;
    }
}

size_t get_block_data(block_ptr blocks, size_t index, uint8_t* buffer, size_t buffer_len) {
    if (!blocks || !blocks->blocks) return 0;

    const size_t BLOCK_SIZE = 16;
    emp::block& b = blocks->blocks[index];

    if (!buffer || buffer_len == 0) {
        return BLOCK_SIZE;
    }

    size_t copy_size = buffer_len < BLOCK_SIZE ? buffer_len : BLOCK_SIZE;
    memcpy(buffer, &b, copy_size);

    return copy_size;
}

void set_block_data(block_ptr blocks, size_t index, const uint8_t* data, size_t data_len) {
    if (!blocks || !blocks->blocks || !data) return;

    const size_t BLOCK_SIZE = 16;
    emp::block& b = blocks->blocks[index];

    size_t copy_size = data_len < BLOCK_SIZE ? data_len : BLOCK_SIZE;
    memcpy(&b, data, copy_size);

    if (copy_size < BLOCK_SIZE) {
        memset(reinterpret_cast<uint8_t*>(&b) + copy_size, 0, BLOCK_SIZE - copy_size);
    }
}

// =============================================================================
// State serialization functions (for persistent storage)
// =============================================================================

int64_t ferret_cot_state_size(FerretCOT_ptr ot) {
    if (!ot || !ot->ferret_cot) return 0;
    return ot->ferret_cot->state_size();
}

int64_t ferret_cot_buffer_state_size(FerretCOT_Buffer_ptr ot) {
    if (!ot || !ot->ferret_cot) return 0;
    return ot->ferret_cot->state_size();
}

int ferret_cot_assemble_state(FerretCOT_ptr ot, uint8_t* buffer, int64_t buffer_size) {
    if (!ot || !ot->ferret_cot || !buffer) return -1;
    int64_t needed = ot->ferret_cot->state_size();
    if (buffer_size < needed) return -1;
    ot->ferret_cot->assemble_state(buffer, buffer_size);
    return 0;
}

int ferret_cot_buffer_assemble_state(FerretCOT_Buffer_ptr ot, uint8_t* buffer, int64_t buffer_size) {
    if (!ot || !ot->ferret_cot || !buffer) return -1;
    int64_t needed = ot->ferret_cot->state_size();
    if (buffer_size < needed) return -1;
    ot->ferret_cot->assemble_state(buffer, buffer_size);
    return 0;
}

int ferret_cot_disassemble_state(FerretCOT_ptr ot, const uint8_t* buffer, int64_t buffer_size) {
    if (!ot || !ot->ferret_cot || !buffer) return -1;
    return ot->ferret_cot->disassemble_state(buffer, buffer_size);
}

int ferret_cot_buffer_disassemble_state(FerretCOT_Buffer_ptr ot, const uint8_t* buffer, int64_t buffer_size) {
    if (!ot || !ot->ferret_cot || !buffer) return -1;
    return ot->ferret_cot->disassemble_state(buffer, buffer_size);
}

bool ferret_cot_is_setup(FerretCOT_ptr ot) {
    if (!ot || !ot->ferret_cot) return false;
    return ot->ferret_cot->is_setup();
}

bool ferret_cot_buffer_is_setup(FerretCOT_Buffer_ptr ot) {
    if (!ot || !ot->ferret_cot) return false;
    return ot->ferret_cot->is_setup();
}