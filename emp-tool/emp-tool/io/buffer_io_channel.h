#ifndef EMP_BUFFER_IO_CHANNEL
#define EMP_BUFFER_IO_CHANNEL

#include <string>
#include <cstring>
#include <stdexcept>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include "emp-tool/io/io_channel.h"

namespace emp {

/**
 * BufferIO - A message-based IO channel for EMP toolkit
 *
 * This IO channel uses internal buffers instead of network sockets,
 * allowing Ferret OT to be used with any transport mechanism
 * (message queues, gRPC, HTTP, etc).
 *
 * Usage:
 * 1. Create BufferIO for each party
 * 2. When Ferret calls send_data_internal, data goes to send_buffer
 * 3. External code calls drain_send_buffer() to get data to transmit
 * 4. External code calls fill_recv_buffer() with received data
 * 5. When Ferret calls recv_data_internal, data comes from recv_buffer
 *
 * Thread safety:
 * - fill_recv_buffer and drain_send_buffer can be called from different threads
 * - recv_data_internal will block if recv_buffer is empty (with timeout)
 */
class BufferIO: public IOChannel<BufferIO> {
public:
    // Send buffer (data written by Ferret, read by external transport)
    char* send_buffer = nullptr;
    int64_t send_size = 0;      // Current data in send buffer
    int64_t send_cap = 0;       // Send buffer capacity

    // Receive buffer (data written by external transport, read by Ferret)
    char* recv_buffer = nullptr;
    int64_t recv_size = 0;      // Current data in recv buffer
    int64_t recv_pos = 0;       // Current read position
    int64_t recv_cap = 0;       // Receive buffer capacity

    // Synchronization
    std::mutex send_mutex;
    std::mutex recv_mutex;
    std::condition_variable recv_cv;

    // Timeout for blocking receive (milliseconds)
    int64_t recv_timeout_ms = 30000;  // 30 second default

    // Error state
    bool has_error = false;
    std::string error_message;

    BufferIO(int64_t initial_cap = 1024 * 1024) {
        send_cap = initial_cap;
        recv_cap = initial_cap;
        send_buffer = new char[send_cap];
        recv_buffer = new char[recv_cap];
        send_size = 0;
        recv_size = 0;
        recv_pos = 0;
    }

    ~BufferIO() {
        if (send_buffer != nullptr) {
            delete[] send_buffer;
        }
        if (recv_buffer != nullptr) {
            delete[] recv_buffer;
        }
    }

    /**
     * Set timeout for blocking receive operations
     */
    void set_recv_timeout(int64_t timeout_ms) {
        recv_timeout_ms = timeout_ms;
    }

    /**
     * Fill the receive buffer with data from external transport
     * This is called by the external code when data arrives
     */
    void fill_recv_buffer(const char* data, int64_t len) {
        std::lock_guard<std::mutex> lock(recv_mutex);

        // Compact buffer if needed
        if (recv_pos > 0 && recv_pos == recv_size) {
            recv_pos = 0;
            recv_size = 0;
        } else if (recv_pos > recv_cap / 2) {
            // Move remaining data to front
            int64_t remaining = recv_size - recv_pos;
            memmove(recv_buffer, recv_buffer + recv_pos, remaining);
            recv_pos = 0;
            recv_size = remaining;
        }

        // Grow buffer if needed
        int64_t available = recv_cap - recv_size;
        if (len > available) {
            int64_t new_cap = recv_cap * 2;
            while (new_cap - recv_size < len) {
                new_cap *= 2;
            }
            char* new_buffer = new char[new_cap];
            memcpy(new_buffer, recv_buffer + recv_pos, recv_size - recv_pos);
            delete[] recv_buffer;
            recv_buffer = new_buffer;
            recv_size = recv_size - recv_pos;
            recv_pos = 0;
            recv_cap = new_cap;
        }

        // Copy data to buffer
        memcpy(recv_buffer + recv_size, data, len);
        recv_size += len;

        // Notify any waiting receivers
        recv_cv.notify_all();
    }

    /**
     * Get available data in receive buffer (non-blocking check)
     */
    int64_t recv_buffer_available() {
        std::lock_guard<std::mutex> lock(recv_mutex);
        return recv_size - recv_pos;
    }

    /**
     * Drain the send buffer - returns data that needs to be transmitted
     * This is called by external code to get data to send
     * Returns the number of bytes copied, or 0 if buffer is empty
     */
    int64_t drain_send_buffer(char* out_buffer, int64_t max_len) {
        std::lock_guard<std::mutex> lock(send_mutex);

        int64_t to_copy = (send_size < max_len) ? send_size : max_len;
        if (to_copy > 0) {
            memcpy(out_buffer, send_buffer, to_copy);

            // Move remaining data to front
            if (to_copy < send_size) {
                memmove(send_buffer, send_buffer + to_copy, send_size - to_copy);
            }
            send_size -= to_copy;
        }
        return to_copy;
    }

    /**
     * Get the entire send buffer as a copy and clear it
     * Returns a pair of (data pointer, length) - caller owns the memory
     */
    std::pair<char*, int64_t> drain_send_buffer_all() {
        std::lock_guard<std::mutex> lock(send_mutex);

        if (send_size == 0) {
            return {nullptr, 0};
        }

        char* data = new char[send_size];
        memcpy(data, send_buffer, send_size);
        int64_t len = send_size;
        send_size = 0;

        return {data, len};
    }

    /**
     * Get current send buffer size (for checking if there's data to send)
     */
    int64_t send_buffer_size() {
        std::lock_guard<std::mutex> lock(send_mutex);
        return send_size;
    }

    /**
     * Clear all buffers
     */
    void clear() {
        {
            std::lock_guard<std::mutex> lock(send_mutex);
            send_size = 0;
        }
        {
            std::lock_guard<std::mutex> lock(recv_mutex);
            recv_size = 0;
            recv_pos = 0;
        }
    }

    /**
     * Set error state - will cause recv_data_internal to throw
     */
    void set_error(const std::string& msg) {
        has_error = true;
        error_message = msg;
        recv_cv.notify_all();  // Wake up any blocking receivers
    }

    /**
     * Internal send - called by Ferret/EMP
     * Appends data to send buffer
     */
    void send_data_internal(const void* data, int64_t len) {
        std::lock_guard<std::mutex> lock(send_mutex);

        // Grow buffer if needed
        if (send_size + len > send_cap) {
            int64_t new_cap = send_cap * 2;
            while (new_cap < send_size + len) {
                new_cap *= 2;
            }
            char* new_buffer = new char[new_cap];
            memcpy(new_buffer, send_buffer, send_size);
            delete[] send_buffer;
            send_buffer = new_buffer;
            send_cap = new_cap;
        }

        memcpy(send_buffer + send_size, data, len);
        send_size += len;
    }

    /**
     * Internal receive - called by Ferret/EMP
     * Reads data from receive buffer, blocking if necessary
     */
    void recv_data_internal(void* data, int64_t len) {
        std::unique_lock<std::mutex> lock(recv_mutex);

        int64_t received = 0;
        char* out = static_cast<char*>(data);

        while (received < len) {
            // Check for error state
            if (has_error) {
                throw std::runtime_error("BufferIO error: " + error_message);
            }

            // Check available data
            int64_t available = recv_size - recv_pos;
            if (available > 0) {
                int64_t to_copy = (available < (len - received)) ? available : (len - received);
                memcpy(out + received, recv_buffer + recv_pos, to_copy);
                recv_pos += to_copy;
                received += to_copy;
            } else {
                // Wait for data with timeout
                auto timeout = std::chrono::milliseconds(recv_timeout_ms);
                if (!recv_cv.wait_for(lock, timeout, [this]() {
                    return (recv_size - recv_pos > 0) || has_error;
                })) {
                    throw std::runtime_error("BufferIO recv timeout");
                }
            }
        }
    }

    /**
     * Flush - no-op for BufferIO since there's no underlying stream
     * But can be used as a signal that a message boundary has been reached
     */
    void flush() {
        // No-op - data is immediately available in send_buffer
    }
};

}  // namespace emp

#endif  // EMP_BUFFER_IO_CHANNEL
