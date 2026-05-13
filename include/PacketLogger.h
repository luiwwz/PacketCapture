#ifndef PACKET_LOGGER_H
#define PACKET_LOGGER_H

#include <string>
#include <fstream>
#include <mutex>

class PacketLogger {
private:
    static std::ofstream logFile;
    static bool loggingEnabled;
    static std::mutex log_mutex;

public:
    static void enableLogging();
    static void disableLogging();
    static bool isLoggingEnabled();
    static void showLog();
    static void log(const std::string& message);
    static void closeLog();
};

#endif
