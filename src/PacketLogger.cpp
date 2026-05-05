#include "PacketLogger.h"
#include <iostream>
#include <cerrno> 
#include <cstring>

std::ofstream PacketLogger::logFile;
bool PacketLogger::loggingEnabled = false;

void PacketLogger::enableLogging() {
    loggingEnabled = true;
    if (logFile.is_open()) {
        logFile.close();
    }
    logFile.open("log.txt", std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "ERROR: Failed to open log.txt! Error: " << strerror(errno) << "\n";
    }
}

void PacketLogger::disableLogging() {
    loggingEnabled = false;
    if (logFile.is_open()) {
        logFile.close();
    }
}

bool PacketLogger::isLoggingEnabled() {
    return loggingEnabled;
}

void PacketLogger::log(const std::string& message) {
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
}

void PacketLogger::closeLog() {
    if (logFile.is_open()) {
        logFile.flush();
        logFile.close();
    }
}

void PacketLogger::showLog() {
    std::ifstream file("log.txt");

    if (!file.is_open()) {
        std::cout << "Log file not found or cannot be opened.\n";
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
}
