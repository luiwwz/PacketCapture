#include "PacketLogger.h"
#include "SynchronizationManager.h"
#include <iostream>
#include <cerrno>
#include <cstring>

std::ofstream PacketLogger::logFile;
bool PacketLogger::loggingEnabled = false;

void PacketLogger::enableLogging() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockLogger();

    loggingEnabled = true;
    if (logFile.is_open()) {
        logFile.close();
    }
    logFile.open("log.txt", std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "ERROR: Failed to open log.txt! Error: " << strerror(errno) << "\n";
    }

    sync->unlockLogger();
}

void PacketLogger::disableLogging() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockLogger();

    loggingEnabled = false;
    if (logFile.is_open()) {
        logFile.close();
    }

    sync->unlockLogger();
}

bool PacketLogger::isLoggingEnabled() {
    return loggingEnabled;
}

void PacketLogger::log(const std::string& message) {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockLogger();

    if (loggingEnabled) {
        if (!logFile.is_open()) {
            std::cerr << "WARNING: Logging enabled but file not open. Reopening...\n";
            logFile.open("log.txt", std::ios::app);
        }

        if (logFile.is_open()) {
            logFile << message << std::endl;
            logFile.flush();
        } else {
            std::cerr << "ERROR: Cannot write to log file!\n";
        }
    } else {
        std::cout << message << std::endl;
    }

    sync->unlockLogger();
}

void PacketLogger::closeLog() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockLogger();

    if (logFile.is_open()) {
        logFile.flush();
        logFile.close();
    }

    sync->unlockLogger();
}

void PacketLogger::showLog() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockLogger();

    std::ifstream file("log.txt");

    if (!file.is_open()) {
        std::cout << "Log file not found or cannot be opened.\n";
        sync->unlockLogger();
        return;
    }

    std::string line;
    std::cout << "\n╔════════════════════════════════╗\n";
    std::cout << "║          Log Contents          ║\n";
    std::cout << "╚════════════════════════════════╝\n";

    while (std::getline(file, line)) {
        std::cout << line << std::endl;
    }

    file.close();
    std::cout << "\n";

    sync->unlockLogger();
}
