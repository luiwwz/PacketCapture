#include "PacketBuffer.h"
#include "ThreadManager.h"

bool PacketBuffer::addPacket(PacketData&& packet) {
    {
        std::lock_guard<std::mutex> lock(mutex);
        queue.push(std::move(packet));   
    }
    packet_available.notify_one();
    return true;
}

bool PacketBuffer::getPacket(PacketData&& packet) {
    std::unique_lock<std::mutex> lock(mutex);
    packet_available.wait(lock, [this] {
        return !queue.empty() || !ThreadManager::getInstance().shouldContinue();
    });
    if (queue.empty()) return false;
    packet = std::move(queue.front());  
    queue.pop();
    return true;
}

bool PacketBuffer::isBufferEmpty() const {
    std::lock_guard<std::mutex> lock(mutex);
    return queue.empty();
}

size_t PacketBuffer::getPacketCount() const {
    std::lock_guard<std::mutex> lock(mutex);
    return queue.size();
}

void PacketBuffer::notifyAll() {
    packet_available.notify_all();
}
