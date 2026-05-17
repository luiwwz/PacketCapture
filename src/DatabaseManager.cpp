#include "DatabaseManager.h"
#include <iostream>
#include <cstring>

void DatabaseManager::initDatabase() {
    std::lock_guard<std::mutex> lock(db_mutex);
    sqlite3_open(DB_NAME, &db);
    sqlite3_exec(db, "PRAGMA journal_mode = WAL;",  nullptr, nullptr, nullptr);
    sqlite3_exec(db, "PRAGMA synchronous = OFF;", nullptr, nullptr, nullptr);

    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS packets ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "src_ip TEXT, dst_ip TEXT,"
        "src_port INTEGER, dst_port INTEGER,"
        "protocol INTEGER, packet_length INTEGER,"
        "is_suspicious INTEGER,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);",
        nullptr, nullptr, nullptr);

    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "src_ip TEXT, dst_ip TEXT,"
        "src_port INTEGER, dst_port INTEGER,"
        "protocol INTEGER, alert_type TEXT, description TEXT,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);",
        nullptr, nullptr, nullptr);
}

void DatabaseManager::flushBatch() {
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
    for (const auto& p : packet_batch) {
        char query[512];
        snprintf(query, sizeof(query),
            "INSERT INTO packets (src_ip,dst_ip,src_port,dst_port,protocol,packet_length,is_suspicious)"
            "VALUES ('%s','%s',%d,%d,%d,%d,%d);",
            p.src_ip, p.dst_ip, p.src_port, p.dst_port,
            p.protocol, p.length, 0);
        sqlite3_exec(db, query, nullptr, nullptr, nullptr);
    }
    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    packet_batch.clear();
}

void DatabaseManager::storePacket(PacketData&& packet, bool is_suspicious) {
    std::lock_guard<std::mutex> lock(db_mutex);
    packet_batch.push_back(std::move(packet));
    if (packet_batch.size() >= BATCH_SIZE) flushBatch();
}

void DatabaseManager::storeAlert(const AlertData& alert) {
    std::lock_guard<std::mutex> lock(db_mutex);
    char query[512];
    snprintf(query, sizeof(query),
        "INSERT INTO alerts (src_ip,dst_ip,src_port,dst_port,protocol,alert_type,description)"
        "VALUES ('%s','%s',%d,%d,%d,'%s','%s');",
        alert.source_ip.c_str(), alert.dest_ip.c_str(),
        alert.source_port, alert.dest_port, alert.protocol,
        alert.alert_type.c_str(), alert.description.c_str());
    sqlite3_exec(db, query, nullptr, nullptr, nullptr);
}

void DatabaseManager::closeDatabase() {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!packet_batch.empty()) flushBatch();  
    if (db) sqlite3_close(db);
}

void DatabaseManager::displayPackets() {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!packet_batch.empty()) flushBatch();
    if (!db) return;
    const char* query = "SELECT * FROM packets ORDER BY timestamp DESC LIMIT 20;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;
    std::cout << "\n===== Recent Packets =====\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::cout << "From: " << sqlite3_column_text(stmt,1)
                  << ":"     << sqlite3_column_int(stmt,3)
                  << " -> " << sqlite3_column_text(stmt,2)
                  << ":"     << sqlite3_column_int(stmt,4)
                  << " ["   << (sqlite3_column_int(stmt,7) ? "SUSPICIOUS" : "NORMAL")
                  << "]\n";
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
        std::cout << "[" << sqlite3_column_text(stmt,6)
                  << "] " << sqlite3_column_text(stmt,7)
                  << " from " << sqlite3_column_text(stmt,1) << "\n";
    }
    sqlite3_finalize(stmt);
}
