#include "Menu.h"
#include "PacketCapturer.h"
#include "PacketLogger.h"
#include "PacketStatistics.h"
#include "DatabaseManager.h"
#include <iostream>
#include <pcap.h>

Menu::Menu() : currentInterface("eth0"), loggingEnabled(false), packetCount(15) {}

std::string Menu::getCurrentInterface() const {
    return currentInterface;
}

bool Menu::isLoggingEnabled() const {
    return loggingEnabled;
}

int Menu::getPacketCount() const {
    return packetCount;
}

void Menu::showMainMenu() {
    int choice;

    while (true) {
        std::cout << "\n╔════════════════════════════════╗\n";
        std::cout << "║   PacketCapturer Menu          ║\n";
        std::cout << "╚════════════════════════════════╝\n";
        std::cout << "1. Start packet capture\n";
        std::cout << "2. Change network interface\n";
        std::cout << "3. Change logging settings\n";
        std::cout << "4. View statistics\n";
        std::cout << "5. Show log\n";
        std::cout << "6. Change packet count\n";
        std::cout << "7. View database packets\n";
        std::cout << "8. View security alerts\n";
        std::cout << "9. Clear Database\n";
	std::cout << "10. View all security alerts (all time)\n";
	std::cout << "11. Exit\n";
        std::cout << "\nCurrent Interface: " << currentInterface << "\n";
        std::cout << "Packet Count: " << packetCount << "\n";
        std::cout << "Logging: " << (loggingEnabled ? "Enabled" : "Disabled") << "\n";
        std::cout << "\nChoose option: ";
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
        case 1:
            startPacketCapture();
            break;
        case 2:
            showInterfaceMenu();
            break;
        case 3:
            showSettingsMenu();
            break;
        case 4:
            PacketStatistics::printStatistics();
            break;
        case 5:
            PacketLogger::showLog();
            break;
        case 6:
            showPacketCountMenu();
            break;
        case 7: {
            DatabaseManager& db = DatabaseManager::getInstance();
	    int limit;
	    std::cout << "How many packets to show?\n";
	    std::cin >> limit;
            db.displayPackets(limit);
            break;
        }

        case 8: {
            DatabaseManager& db = DatabaseManager::getInstance();
            db.displayAlerts();
            break;
        }

	case 9: {
	    DatabaseManager& db = DatabaseManager::getInstance();
            db.clearDatabase();
            std::cout << "Database cleared.\n";
            break;
        
	}
	
	case 10: {
            DatabaseManager& db = DatabaseManager::getInstance();
            db.displayAllAlerts();
            break; 
        }	

        case 11:
            std::cout << "Exiting...\n";
            return;

        default:
            std::cout << "Invalid option!\n";
        }
    }
}

void Menu::showInterfaceMenu() {
    int choice;

    std::cout << "\nAvailable interfaces:\n";
    std::cout << "1. eth0\n";
    std::cout << "2. lo\n";
    std::cout << "3. any (eth0 and lo)\n";

    std::cout << "\nChoose interface: ";
    std::cin >> choice;
    std::cin.ignore();

    switch (choice) {
    case 1:
        currentInterface = "eth0";
        std::cout << "Interface changed to: eth0\n";
        break;
    case 2:
        currentInterface = "lo";
        std::cout << "Interface changed to: lo\n";
        break;
    case 3:
        currentInterface = "any";
        std::cout << "Interface changed to: any\n";
        break;
    default:
        std::cout << "Invalid option!\n";
    }
}

void Menu::showSettingsMenu() {
    int choice;

    std::cout << "\nSettings:\n";
    std::cout << "1. Enable logging\n";
    std::cout << "2. Disable logging\n";
    std::cout << "3. Back to main menu\n";
    std::cout << "Choose option: ";
    std::cin >> choice;
    std::cin.ignore();

    switch (choice) {
    case 1:
        loggingEnabled = true;
        PacketLogger::enableLogging();
        std::cout << "Logging enabled\n";
        break;
    case 2:
        loggingEnabled = false;
        PacketLogger::disableLogging();
        std::cout << "Logging disabled\n";
        break;
    case 3:
        return;
    default:
        std::cout << "Invalid option!\n";
    }
}

void Menu::showPacketCountMenu() {
    int count;

    std::cout << "\n=== Change Packet Count ===\n";
    std::cout << "Current packet count: " << packetCount << "\n";
    std::cout << "Enter number of packets to capture (0 for infinite): ";
    std::cin >> count;
    std::cin.ignore();

    if (count >= 0) {
        packetCount = count;
        std::cout << "Packet count set to: " << packetCount << "\n";
    } else {
        std::cout << "Invalid input! Packet count remains: " << packetCount << "\n";
    }
}

void Menu::startPacketCapture() {
    std::string ip;
    int protocolChoice;

    std::cout << "\n=== Packet Capture Settings ===\n";

    std::cout << "Please enter IP address (0 for all): ";
    std::cin >> ip;
    std::cin.ignore();

    std::cout << "Choose protocol:\n";
    std::cout << "1 - all\n2 - tcp\n3 - udp\n4 - icmp\n5 - arp\n";
    std::cout << "Choose option: ";
    std::cin >> protocolChoice;
    std::cin.ignore();

    std::cout << "\nStarting capture on " << currentInterface << "...\n";
    std::cout << "Will capture " << packetCount << " packets...\n";

    PacketCapturer capturer(currentInterface);
    capturer.startCapture(ip, protocolChoice, packetCount);

    std::cout << "\nCapture stopped. Returning to menu...\n";
}
