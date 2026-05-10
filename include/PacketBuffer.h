#ifndef PACKET_BUFFER_H
#define PACKET_BUFFER_H

#include "RingBuffer.h"
#include <sys/mman.h>
#include <fcntl.h>

class PacketBuffer {
private:
    static PacketBuffer* instance;
    RingBuffer<PacketData, 256>* ring_buffer;
    void* shared_memory;
    int shm_fd;
    const char* SHM_NAME;
    const size_t SHM_SIZE;

    PacketBuffer();
    ~PacketBuffer();

public:
    static PacketBuffer* getInstance();

    void initSharedMemory();
    void destroySharedMemory();

    bool addPacket(const PacketData& packet);
    bool getPacket(PacketData& packet);
    bool peekPacket(PacketData& packet) const;
    bool isBufferFull() const;
    bool isBufferEmpty() const;
    size_t getPacketCount() const;
};

#endif
