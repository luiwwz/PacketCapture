#include "DatabaseManager.h"
#include <iostream>

void DatabaseManager::initDatabase() {
    std::lock_guard<std::mutex> lock(db_mutex);

    if (sqlite3_open(DB_NAME, &db) != SQLITE_OK) {
        std::cerr << "ERROR: Cannot open database: " << sqlite3_errmsg(db) << "\n";
        db = nullptr;
        return;
    }

    session_start = time(nullptr);

    sqlite3_exec(db, "PRAGMA journal_mode = WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db, "PRAGMA synchronous = OFF;",  nullptr, nullptr, nullptr);

    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS packets ("
        "id             INTEGER PRIMARY KEY AUTOINCREMENT,"
        "src_ip         TEXT,"
        "dst_ip         TEXT,"
        "src_port       INTEGER,"
        "dst_port       INTEGER,"
        "protocol       INTEGER,"
        "packet_length  INTEGER,"
        "is_suspicious  INTEGER,"
        "timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP);",
        nullptr, nullptr, nullptr);

    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS alerts ("
        "id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "src_ip      TEXT,"
        "dst_ip      TEXT,"
        "src_port    INTEGER,"
        "dst_port    INTEGER,"
        "protocol    INTEGER,"
        "alert_type  TEXT,"
        "description TEXT,"
        "timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP);",
        nullptr, nullptr, nullptr);
}

void DatabaseManager::flushBatch() {
    if (!db || packet_batch.empty()) return;

    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "INSERT INTO packets "
        "(src_ip, dst_ip, src_port, dst_port, protocol, packet_length, is_suspicious) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);",
        -1, &stmt, nullptr);

    for (const auto& [p, suspicious] : packet_batch) {
        sqlite3_bind_text(stmt, 1, p.src_ip,    -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, p.dst_ip,    -1, SQLITE_STATIC);
        sqlite3_bind_int (stmt, 3, p.src_port);
        sqlite3_bind_int (stmt, 4, p.dst_port);
        sqlite3_bind_int (stmt, 5, p.protocol);
        sqlite3_bind_int (stmt, 6, p.length);
        sqlite3_bind_int (stmt, 7, suspicious ? 1 : 0); 

        sqlite3_step(stmt);
        sqlite3_reset(stmt);  
    }

    sqlite3_finalize(stmt);
    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    packet_batch.clear();
}

void DatabaseManager::storePacket(PacketData&& packet, bool is_suspicious) {
    std::lock_guard<std::mutex> lock(db_mutex);
    packet_batch.push_back({std::move(packet), is_suspicious});
    if (packet_batch.size() >= BATCH_SIZE) flushBatch();
}

void DatabaseManager::storeAlert(const AlertData& alert) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return;

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "INSERT INTO alerts "
        "(src_ip, dst_ip, src_port, dst_port, protocol, alert_type, description) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);",
        -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, alert.source_ip.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, alert.dest_ip.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 3, alert.source_port);
    sqlite3_bind_int (stmt, 4, alert.dest_port);
    sqlite3_bind_int (stmt, 5, alert.protocol);
    sqlite3_bind_text(stmt, 6, alert.alert_type.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, alert.description.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void DatabaseManager::closeDatabase() {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!packet_batch.empty()) flushBatch();
    if (db) {
        sqlite3_close(db);
        db = nullptr;  
    }
}

void DatabaseManager::displayPackets(int limit) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!packet_batch.empty()) flushBatch();
    if (!db) return;

    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?;",
        -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, limit);

    std::cout << "\n===== Recent Packets (last " << limit << ") =====\n";

    while (sqlite3_step(stmt) == SQLITE_ROW) {
    int    id         = sqlite3_column_int (stmt, 0);
    auto   src_ip     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    auto   dst_ip     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    int    src_port   = sqlite3_column_int (stmt, 3);
    int    dst_port   = sqlite3_column_int (stmt, 4);
    int    protocol   = sqlite3_column_int (stmt, 5);
    int    length     = sqlite3_column_int (stmt, 6);
    bool   suspicious = sqlite3_column_int (stmt, 7) != 0;
    auto   timestamp  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));

    const char* proto_name = (protocol == 6)  ? "TCP"  :
                             (protocol == 17) ? "UDP"  :
                             (protocol == 1)  ? "ICMP" : "OTHER";

    std::cout << "[#" << id << "] "
              << (timestamp ? timestamp : "?") << "\n"
              << "  " << (src_ip ? src_ip : "?") << ":" << src_port
              << " -> " << (dst_ip ? dst_ip : "?") << ":" << dst_port << "\n"
              << "  Protocol: " << proto_name
              << "  Size: " << length << " bytes"
              << "  [" << (suspicious ? "SUSPICIOUS" : "NORMAL") << "]\n\n";
    }
    sqlite3_finalize(stmt);
}

void DatabaseManager::displayAlerts() {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return;
 
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT * FROM alerts "
        "WHERE timestamp >= datetime(?, 'unixepoch') "
        "ORDER BY timestamp ASC;",
        -1, &stmt, nullptr);
 
    char ts[32];
    snprintf(ts, sizeof(ts), "%ld", (long)session_start);
    sqlite3_bind_text(stmt, 1, ts, -1, SQLITE_STATIC);
 
    std::cout << "\n===== Security Alerts (this session) =====\n";
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* alert_type  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        const char* description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        const char* src_ip      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* timestamp   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
 
        std::cout << "[" << (timestamp   ? timestamp   : "?") << "] "
                  << "[" << (alert_type  ? alert_type  : "?") << "] "
                         << (description ? description : "?")
                  << " from " << (src_ip ? src_ip : "?") << "\n";
        count++;
    }
    sqlite3_finalize(stmt);
 
    if (count == 0) std::cout << "No alerts this session.\n";
}
 
void DatabaseManager::displayAllAlerts() {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return;
 
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT * FROM alerts ORDER BY timestamp ASC;",
        -1, &stmt, nullptr);
 
    std::cout << "\n===== All Security Alerts (all time) =====\n";
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* alert_type  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        const char* description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        const char* src_ip      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* timestamp   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
 
        std::cout << "[" << (timestamp   ? timestamp   : "?") << "] "
                  << "[" << (alert_type  ? alert_type  : "?") << "] "
                         << (description ? description : "?")
                  << " from " << (src_ip ? src_ip : "?") << "\n";
        count++;
    }
    sqlite3_finalize(stmt);
 
    if (count == 0) std::cout << "No alerts found.\n";
}

void DatabaseManager::clearDatabase() {
    std::lock_guard<std::mutex> lock(db_mutex);
    packet_batch.clear();
    sqlite3_exec(db, "DELETE FROM sqlite_sequence WHERE name='packets';", nullptr, nullptr, nullptr);
    sqlite3_exec(db, "DELETE FROM sqlite_sequence WHERE name='alerts';",  nullptr, nullptr, nullptr);
    sqlite3_exec(db, "DELETE FROM packets;", nullptr, nullptr, nullptr);
    sqlite3_exec(db, "DELETE FROM alerts;",  nullptr, nullptr, nullptr);
    sqlite3_exec(db, "VACUUM;", nullptr, nullptr, nullptr); 
}
