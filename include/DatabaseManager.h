#ifndef DATABASE_MANAGER_H
#define DATABASE_MANAGER_H

#include "IDSDetector.h"
#include <sqlite3.h>
#include <string>
#include <mutex>

class DatabaseManager {
private:
    static DatabaseManager* instance;
    sqlite3* db;
    const char* DB_NAME;
    std::mutex db_mutex; 

    DatabaseManager();
    ~DatabaseManager();

public:
    static DatabaseManager* getInstance();
    void initDatabase();
    void closeDatabase();
    void storePacket(const PacketData& packet, bool is_suspicious);
    void storeAlert(const AlertData& alert);
    void displayPackets();
    void displayAlerts();
};

#endif
