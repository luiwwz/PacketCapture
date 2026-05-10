#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <cstring>
#include <cstdint>

struct PacketData {
    uint8_t data[65535];
    uint32_t length;
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

template <typename T, size_t CAPACITY>
class RingBuffer {
private:
    T buffer[CAPACITY];
    size_t write_pos;
    size_t read_pos;
    size_t count;

public:
    RingBuffer() : write_pos(0), read_pos(0), count(0) {}

    bool push(const T& element) {
        if (count >= CAPACITY) {
            return false;
        }
        buffer[write_pos] = element;
        write_pos = (write_pos + 1) % CAPACITY;
        count++;
        return true;
    }

    bool pop(T& element) {
        if (count == 0) {
            return false;
        }
        element = buffer[read_pos];
        read_pos = (read_pos + 1) % CAPACITY;
        count--;
        return true;
    }

    bool peek(T& element) const {
        if (count == 0) {
            return false;
        }
        element = buffer[read_pos];
        return true;
    }

    bool isFull() const {
        return count >= CAPACITY;
    }

    bool isEmpty() const {
        return count == 0;
    }

    size_t getCount() const {
        return count;
    }

    size_t getCapacity() const {
        return CAPACITY;
    }
};

#endif
