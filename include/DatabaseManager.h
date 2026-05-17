#ifndef DATABASE_MANAGER_H
#define DATABASE_MANAGER_H

#include "PacketData.h"
#include <sqlite3.h>
#include <string>
#include <mutex>
#include <vector>

class DatabaseManager {
private:

    sqlite3* db = nullptr;
    const char* DB_NAME = "packet_sniffer.db";
    std::mutex db_mutex;

    std::vector<PacketData> packet_batch;
    static constexpr int BATCH_SIZE = 100;
    void flushBatch(); 

    DatabaseManager() = default;
    ~DatabaseManager() = default;

public:

    static DatabaseManager& getInstance() {
        static DatabaseManager instance;
        return instance;
    }

    void initDatabase();
    void closeDatabase();
    void storePacket(PacketData&& packet, bool is_suspicious);
    void storeAlert(const AlertData& alert);
    void displayPackets();
    void displayAlerts();
};

#endif
