#ifndef PACKET_BUFFER_H
#define PACKET_BUFFER_H

#include "RingBuffer.h" 
#include <queue>
#include <mutex>
#include <condition_variable>

class PacketBuffer {
private:
    static PacketBuffer* instance;

    std::queue<PacketData> queue;
    mutable std::mutex mutex;
    std::condition_variable packet_available;

    PacketBuffer() = default;

public:
    static PacketBuffer* getInstance();

    bool addPacket(const PacketData& packet);

    bool getPacket(PacketData& packet);

    bool   isBufferEmpty() const;
    size_t getPacketCount() const;

    void notifyAll();
};

#endif
