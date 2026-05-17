#include "ThreadManager.h"
#include "PacketBuffer.h"
#include "DatabaseManager.h"
#include "IDSDetector.h"
#include <iostream>

std::atomic<bool> ThreadManager::should_exit(false);

ThreadManager::ThreadManager() {}

ThreadManager& ThreadManager::getInstance() {
    static ThreadManager instance;
    return instance;
}

void ThreadManager::setupSignalHandlers() {
    signal(SIGINT,  ThreadManager::signalHandler);
    signal(SIGTERM, ThreadManager::signalHandler);
}

void ThreadManager::signalHandler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        should_exit = true;
        PacketBuffer::getInstance().notifyAll();
    }
}

static void analyzerLoop(int id) {
    DatabaseManager& db  = DatabaseManager::getInstance();
    IDSDetector detector;
    PacketBuffer& uf = PacketBuffer::getInstance();
    ThreadManager& tm  = ThreadManager::getInstance();

    while (true) {
        PacketData packet;

        if (!uf.getPacket(std::move(packet))) {
            if (!tm.shouldContinue()) break;
            continue;
        }

        AlertData* alert = detector.detectThreats(packet);
        bool suspicious  = (alert != nullptr);

        db.storePacket(std::move(packet), suspicious);

        if (alert != nullptr) {
            db.storeAlert(*alert);
            std::cout << "[ALERT][Thread " << id << "] "
                      << alert->alert_type << ": "
                      << alert->description
                      << " from " << alert->source_ip << "\n";
            delete alert;
        }
    }
}

void ThreadManager::spawnAnalyzers(int count) {
    for (int i = 0; i < count; ++i) {
        analyzer_threads.emplace_back(analyzerLoop, i + 1);
    }
}

void ThreadManager::terminateAnalyzers() {
    should_exit = true;
    PacketBuffer::getInstance().notifyAll();
}

void ThreadManager::waitForAnalyzers() {
    for (auto& t : analyzer_threads) {
        if (t.joinable()) t.join();
    }
    analyzer_threads.clear();
}

bool ThreadManager::shouldContinue() const {
    return !should_exit;
}
