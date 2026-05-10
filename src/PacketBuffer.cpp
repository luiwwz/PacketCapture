#include "PacketBuffer.h"
#include "SynchronizationManager.h"
#include <iostream>
#include <cstring>
#include <unistd.h>

PacketBuffer* PacketBuffer::instance = nullptr;

PacketBuffer::PacketBuffer()
    : ring_buffer(nullptr),
      shared_memory(nullptr),
      shm_fd(-1),
      SHM_NAME("/packet_sniffer_shm"),
      SHM_SIZE(sizeof(RingBuffer<PacketData, 256>)) {}

PacketBuffer* PacketBuffer::getInstance() {
    if (instance == nullptr) {
        instance = new PacketBuffer();
    }
    return instance;
}

void PacketBuffer::initSharedMemory() {
    shm_unlink(SHM_NAME);

    shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        std::cerr << "Failed to create shared memory\n";
        return;
    }

    if (ftruncate(shm_fd, SHM_SIZE) == -1) {
        std::cerr << "Failed to set shared memory size\n";
        close(shm_fd);
        return;
    }

    shared_memory = mmap(nullptr, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shared_memory == MAP_FAILED) {
        std::cerr << "Failed to map shared memory\n";
        close(shm_fd);
        return;
    }

    ring_buffer = new (shared_memory) RingBuffer<PacketData, 256>();
}

void PacketBuffer::destroySharedMemory() {
    if (ring_buffer != nullptr) {
        ring_buffer->~RingBuffer();
    }
    if (shared_memory != nullptr && shared_memory != MAP_FAILED) {
        munmap(shared_memory, SHM_SIZE);
    }
    if (shm_fd != -1) {
        close(shm_fd);
    }
    shm_unlink(SHM_NAME);
}

bool PacketBuffer::addPacket(const PacketData& packet) {
    if (ring_buffer == nullptr) {
        return false;
    }

    SynchronizationManager* sync_mgr = SynchronizationManager::getInstance();
    sync_mgr->lockBuffer();

    bool result = ring_buffer->push(packet);

    sync_mgr->unlockBuffer();
    sync_mgr->signalPacketAvailable();

    return result;
}

bool PacketBuffer::getPacket(PacketData& packet) {
    if (ring_buffer == nullptr) {
        return false;
    }

    SynchronizationManager* sync_mgr = SynchronizationManager::getInstance();
    sync_mgr->lockBuffer();

    bool result = ring_buffer->pop(packet);

    sync_mgr->unlockBuffer();

    return result;
}

bool PacketBuffer::peekPacket(PacketData& packet) const {
    if (ring_buffer == nullptr) {
        return false;
    }

    return ring_buffer->peek(packet);
}

bool PacketBuffer::isBufferFull() const {
    if (ring_buffer == nullptr) {
        return false;
    }
    return ring_buffer->isFull();
}

bool PacketBuffer::isBufferEmpty() const {
    if (ring_buffer == nullptr) {
        return true;
    }
    return ring_buffer->isEmpty();
}

size_t PacketBuffer::getPacketCount() const {
    if (ring_buffer == nullptr) {
        return 0;
    }
    return ring_buffer->getCount();
}
