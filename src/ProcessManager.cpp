#include "ProcessManager.h"
#include "PacketBuffer.h"
#include "SynchronizationManager.h"
#include "DatabaseManager.h"
#include "IDSDetector.h"
#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <cstring>

ProcessManager* ProcessManager::instance = nullptr;
volatile bool ProcessManager::should_exit = false;

ProcessManager::ProcessManager() : num_analyzers(0) {}

ProcessManager* ProcessManager::getInstance() {
    if (instance == nullptr) {
        instance = new ProcessManager();
    }
    return instance;
}

void ProcessManager::setupSignalHandlers() {
    signal(SIGINT, ProcessManager::signalHandler);
    signal(SIGTERM, ProcessManager::signalHandler);
}

void ProcessManager::signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        should_exit = true;
    }
}

void ProcessManager::spawnAnalyzers(int count) {
    num_analyzers = count;

    for (int i = 0; i < count; ++i) {
        pid_t pid = fork();

        if (pid == 0) {
            PacketBuffer* buffer = PacketBuffer::getInstance();
            DatabaseManager* db = DatabaseManager::getInstance();
            IDSDetector detector;
            SynchronizationManager* sync = SynchronizationManager::getInstance();

            while (!should_exit) {
                sync->waitPacketAvailable();

                PacketData packet;
                if (buffer->getPacket(packet)) {
                    AlertData* alert = detector.detectThreats(packet);
                    bool is_suspicious = (alert != nullptr);

                    db->storePacket(packet, is_suspicious);

                    if (alert != nullptr) {
                        db->storeAlert(*alert);
                        std::cout << "[ALERT] " << alert->alert_type << ": " 
                                  << alert->description << " from " 
                                  << alert->source_ip << "\n";
                        delete alert;
                    }
                }
            }

            exit(0);
        } else if (pid > 0) {
            analyzer_processes.push_back(pid);
        } else {
            std::cerr << "Failed to fork analyzer process\n";
        }
    }
}

void ProcessManager::terminateAnalyzers() {
    for (pid_t pid : analyzer_processes) {
        kill(pid, SIGTERM);
    }
}

void ProcessManager::waitForAnalyzers() {
    for (pid_t pid : analyzer_processes) {
        waitpid(pid, nullptr, 0);
    }
    analyzer_processes.clear();
}

bool ProcessManager::shouldContinue() const {
    return !should_exit;
}
