#ifndef PACKET_BUFFER_H
#define PACKET_BUFFER_H

#include "PacketData.h"
#include <queue>
#include <mutex>
#include <condition_variable>

class PacketBuffer {
private:
   
    std::queue<PacketData> queue;
    mutable std::mutex mutex;
    std::condition_variable packet_available;

    PacketBuffer() = default;

public:
    static PacketBuffer& getInstance() {
        static PacketBuffer instance;
        return instance;
    }   

    bool addPacket(PacketData&& packet);
    bool getPacket(PacketData&& packet);

    bool   isBufferEmpty() const;
    size_t getPacketCount() const;

    void notifyAll();
};

#endif
