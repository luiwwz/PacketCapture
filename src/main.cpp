#include "Menu.h"
#include "PacketBuffer.h"
#include "DatabaseManager.h"
#include "ThreadManager.h"
#include <iostream>

int main() {
    DatabaseManager& db = DatabaseManager::getInstance();
    db.initDatabase();

    ThreadManager& tm = ThreadManager::getInstance();
    tm.setupSignalHandlers();
    tm.spawnAnalyzers(2);

    Menu menu;
    menu.showMainMenu();

    std::cout << "\nShutting down...\n";

    tm.terminateAnalyzers();
    tm.waitForAnalyzers();

    db.displayPackets();
    db.displayAlerts();
    db.closeDatabase();

    std::cout << "Cleanup completed. Goodbye!\n";
    return 0;
}
