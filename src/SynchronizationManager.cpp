#include "SynchronizationManager.h"
#include <iostream>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

SynchronizationManager* SynchronizationManager::instance = nullptr;

SynchronizationManager::SynchronizationManager()
    : packet_sem_name("/packet_available"),
      buffer_sem_name("/buffer_ready") {
    pthread_mutex_init(&logger_mutex, nullptr);
    pthread_mutex_init(&statistics_mutex, nullptr);
    pthread_mutex_init(&buffer_mutex, nullptr);
}

SynchronizationManager* SynchronizationManager::getInstance() {
    if (instance == nullptr) {
        instance = new SynchronizationManager();
    }
    return instance;
}

void SynchronizationManager::initSemaphores() {
    sem_unlink(packet_sem_name.c_str());
    sem_unlink(buffer_sem_name.c_str());

    packet_available = sem_open(packet_sem_name.c_str(), O_CREAT, 0644, 0);
    if (packet_available == SEM_FAILED) {
        std::cerr << "Failed to create packet_available semaphore\n";
    }

    buffer_ready = sem_open(buffer_sem_name.c_str(), O_CREAT, 0644, 1);
    if (buffer_ready == SEM_FAILED) {
        std::cerr << "Failed to create buffer_ready semaphore\n";
    }
}

void SynchronizationManager::destroySemaphores() {
    if (packet_available != SEM_FAILED) {
        sem_close(packet_available);
        sem_unlink(packet_sem_name.c_str());
    }
    if (buffer_ready != SEM_FAILED) {
        sem_close(buffer_ready);
        sem_unlink(buffer_sem_name.c_str());
    }
}

SynchronizationManager::~SynchronizationManager() {
    destroySemaphores();
    pthread_mutex_destroy(&logger_mutex);
    pthread_mutex_destroy(&statistics_mutex);
    pthread_mutex_destroy(&buffer_mutex);
}

void SynchronizationManager::waitPacketAvailable() {
    if (packet_available != SEM_FAILED) {
        sem_wait(packet_available);
    }
}

void SynchronizationManager::signalPacketAvailable() {
    if (packet_available != SEM_FAILED) {
        sem_post(packet_available);
    }
}

void SynchronizationManager::waitBufferReady() {
    if (buffer_ready != SEM_FAILED) {
        sem_wait(buffer_ready);
    }
}

void SynchronizationManager::signalBufferReady() {
    if (buffer_ready != SEM_FAILED) {
        sem_post(buffer_ready);
    }
}

void SynchronizationManager::lockLogger() {
    pthread_mutex_lock(&logger_mutex);
}

void SynchronizationManager::unlockLogger() {
    pthread_mutex_unlock(&logger_mutex);
}

void SynchronizationManager::lockStatistics() {
    pthread_mutex_lock(&statistics_mutex);
}

void SynchronizationManager::unlockStatistics() {
    pthread_mutex_unlock(&statistics_mutex);
}

void SynchronizationManager::lockBuffer() {
    pthread_mutex_lock(&buffer_mutex);
}

void SynchronizationManager::unlockBuffer() {
    pthread_mutex_unlock(&buffer_mutex);
}
