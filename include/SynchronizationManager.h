#ifndef SYNCHRONIZATION_MANAGER_H
#define SYNCHRONIZATION_MANAGER_H

#include <semaphore.h>
#include <pthread.h>
#include <string>

class SynchronizationManager {
private:
    static SynchronizationManager* instance;
    sem_t* packet_available;
    sem_t* buffer_ready;
    pthread_mutex_t logger_mutex;
    pthread_mutex_t statistics_mutex;
    pthread_mutex_t buffer_mutex;
    std::string packet_sem_name;
    std::string buffer_sem_name;

    SynchronizationManager();

public:
    static SynchronizationManager* getInstance();
    ~SynchronizationManager();

    void initSemaphores();
    void destroySemaphores();

    void waitPacketAvailable();
    void signalPacketAvailable();
    void waitBufferReady();
    void signalBufferReady();

    void lockLogger();
    void unlockLogger();
    void lockStatistics();
    void unlockStatistics();
    void lockBuffer();
    void unlockBuffer();
};

class MutexGuard {
private:
    pthread_mutex_t* mutex;

public:
    MutexGuard(pthread_mutex_t* m) : mutex(m) {
        pthread_mutex_lock(mutex);
    }
    ~MutexGuard() {
        pthread_mutex_unlock(mutex);
    }
};

#endif
