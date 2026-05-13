#include "PacketLogger.h"
#include <iostream>
#include <cerrno>
#include <cstring>

std::ofstream PacketLogger::logFile;
bool PacketLogger::loggingEnabled = false;
std::mutex PacketLogger::log_mutex;

void PacketLogger::enableLogging() {
    std::lock_guard<std::mutex> lock(log_mutex);
    loggingEnabled = true;
    if (logFile.is_open()) logFile.close();
    logFile.open("log.txt", std::ios::app);
    if (!logFile.is_open())
        std::cerr << "ERROR: Failed to open log.txt: " << strerror(errno) << "\n";
}

void PacketLogger::disableLogging() {
    std::lock_guard<std::mutex> lock(log_mutex);
    loggingEnabled = false;
    if (logFile.is_open()) logFile.close();
}

bool PacketLogger::isLoggingEnabled() { return loggingEnabled; }

void PacketLogger::log(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (loggingEnabled) {
        if (!logFile.is_open()) logFile.open("log.txt", std::ios::app);
        if (logFile.is_open()) logFile << message << std::endl;
        else std::cerr << "ERROR: Cannot write to log file!\n";
    } else {
        std::cout << message << std::endl;
    }
}

void PacketLogger::closeLog() {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (logFile.is_open()) { logFile.flush(); logFile.close(); }
}

void PacketLogger::showLog() {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ifstream file("log.txt");
    if (!file.is_open()) { std::cout << "Log file not found.\n"; return; }
    std::cout << "\n╔════════════════════════════════╗\n"
              << "║          Log Contents          ║\n"
              << "╚════════════════════════════════╝\n";
    std::string line;
    while (std::getline(file, line)) std::cout << line << "\n";
}
