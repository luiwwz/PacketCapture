#include "Menu.h"
#include "PacketBuffer.h"
#include "DatabaseManager.h"
#include "ProcessManager.h"
#include "SynchronizationManager.h"
#include <iostream>

int main() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->initSemaphores();

    PacketBuffer* buffer = PacketBuffer::getInstance();
    buffer->initSharedMemory();

    DatabaseManager* db = DatabaseManager::getInstance();
    db->initDatabase();

    ProcessManager* pm = ProcessManager::getInstance();
    pm->setupSignalHandlers();
    pm->spawnAnalyzers(2);

    Menu menu;
    menu.showMainMenu();

    std::cout << "\nShutting down...\n";

    pm->terminateAnalyzers();
    pm->waitForAnalyzers();

    db->displayPackets();
    db->displayAlerts();
    db->closeDatabase();

    buffer->destroySharedMemory();
    sync->destroySemaphores();

    std::cout << "Cleanup completed. Goodbye!\n";

    return 0;
}

