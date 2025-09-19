#include "emp_bridge.h"
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>

using namespace emp;

struct NetIO_t {
    NetIO* netio;
};

struct FerretCOT_t {
    FerretCOT<NetIO>* ferret_cot;
};

struct block_t {
    block* blocks;
};

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