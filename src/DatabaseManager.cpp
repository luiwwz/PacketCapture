#include "DatabaseManager.h"
#include <iostream>
#include <cstring>

DatabaseManager* DatabaseManager::instance = nullptr;

DatabaseManager::DatabaseManager()
    : db(nullptr), DB_NAME("packet_sniffer.db") {}

DatabaseManager* DatabaseManager::getInstance() {
    if (instance == nullptr)
        instance = new DatabaseManager();
    return instance;
}

void DatabaseManager::initDatabase() {
    std::lock_guard<std::mutex> lock(db_mutex);
    int rc = sqlite3_open(DB_NAME, &db);
    if (rc) { std::cerr << "Can't open database: " << sqlite3_errmsg(db) << "\n"; return; }

    const char* packets_table =
        "CREATE TABLE IF NOT EXISTS packets ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,"
        "src_port INTEGER, dst_port INTEGER,"
        "protocol INTEGER, packet_length INTEGER,"
        "is_suspicious INTEGER,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)";

    const char* alerts_table =
        "CREATE TABLE IF NOT EXISTS alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,"
        "src_port INTEGER, dst_port INTEGER,"
        "protocol INTEGER, alert_type TEXT, description TEXT,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)";

    char* err = nullptr;
    sqlite3_exec(db, packets_table, nullptr, nullptr, &err);
    if (err) { std::cerr << "SQL error: " << err << "\n"; sqlite3_free(err); }
    sqlite3_exec(db, alerts_table, nullptr, nullptr, &err);
    if (err) { std::cerr << "SQL error: " << err << "\n"; sqlite3_free(err); }
}

void DatabaseManager::closeDatabase() {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (db) sqlite3_close(db);
}

void DatabaseManager::storePacket(const PacketData& packet, bool is_suspicious) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return;
    char query[512];
    snprintf(query, sizeof(query),
        "INSERT INTO packets (src_ip,dst_ip,src_port,dst_port,protocol,packet_length,is_suspicious)"
        "VALUES ('%s','%s',%d,%d,%d,%d,%d);",
        packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port,
        packet.protocol, packet.length, is_suspicious ? 1 : 0);
    char* err = nullptr;
    sqlite3_exec(db, query, nullptr, nullptr, &err);
    if (err) { std::cerr << "SQL error: " << err << "\n"; sqlite3_free(err); }
}

void DatabaseManager::storeAlert(const AlertData& alert) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return;
    char query[512];
    snprintf(query, sizeof(query),
        "INSERT INTO alerts (src_ip,dst_ip,src_port,dst_port,protocol,alert_type,description)"
        "VALUES ('%s','%s',%d,%d,%d,'%s','%s');",
        alert.source_ip.c_str(), alert.dest_ip.c_str(),
        alert.source_port, alert.dest_port, alert.protocol,
        alert.alert_type.c_str(), alert.description.c_str());
    char* err = nullptr;
    sqlite3_exec(db, query, nullptr, nullptr, &err);
    if (err) { std::cerr << "SQL error: " << err << "\n"; sqlite3_free(err); }
}

void DatabaseManager::displayPackets() {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return;
    const char* query = "SELECT * FROM packets ORDER BY timestamp DESC LIMIT 20;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;
    std::cout << "\n===== Recent Packets =====\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::cout << "From: " << sqlite3_column_text(stmt,1) << ":" << sqlite3_column_int(stmt,3)
                  << " -> " << sqlite3_column_text(stmt,2) << ":" << sqlite3_column_int(stmt,4)
                  << " Protocol: " << sqlite3_column_int(stmt,5)
                  << " [" << (sqlite3_column_int(stmt,7) ? "SUSPICIOUS" : "NORMAL") << "]\n";
    }
    sqlite3_finalize(stmt);
}

void DatabaseManager::displayAlerts() {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return;
    const char* query = "SELECT * FROM alerts ORDER BY timestamp DESC;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;
    std::cout << "\n===== Security Alerts =====\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::cout << "[" << sqlite3_column_text(stmt,6) << "] "
                  << sqlite3_column_text(stmt,7) << " from "
                  << sqlite3_column_text(stmt,1) << "\n";
    }
    sqlite3_finalize(stmt);
}
