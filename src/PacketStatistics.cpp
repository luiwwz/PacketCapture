#include "PacketStatistics.h"
#include "SynchronizationManager.h"
#include <iostream>

int PacketStatistics::totalPackets = 0;
int PacketStatistics::ipv4Packets = 0;
int PacketStatistics::tcpPackets = 0;
int PacketStatistics::udpPackets = 0;
int PacketStatistics::icmpPackets = 0;
int PacketStatistics::arpPackets = 0;

void PacketStatistics::incrementTotal() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    totalPackets++;
    sync->unlockStatistics();
}

void PacketStatistics::incrementIPv4() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    ipv4Packets++;
    sync->unlockStatistics();
}

void PacketStatistics::incrementTCP() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    tcpPackets++;
    sync->unlockStatistics();
}

void PacketStatistics::incrementUDP() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    udpPackets++;
    sync->unlockStatistics();
}

void PacketStatistics::incrementICMP() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    icmpPackets++;
    sync->unlockStatistics();
}

void PacketStatistics::incrementARP() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    arpPackets++;
    sync->unlockStatistics();
}

int PacketStatistics::getTotalPackets() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    int result = totalPackets;
    sync->unlockStatistics();
    return result;
}

int PacketStatistics::getIPv4Packets() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    int result = ipv4Packets;
    sync->unlockStatistics();
    return result;
}

int PacketStatistics::getTCPPackets() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    int result = tcpPackets;
    sync->unlockStatistics();
    return result;
}

int PacketStatistics::getUDPPackets() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    int result = udpPackets;
    sync->unlockStatistics();
    return result;
}

int PacketStatistics::getICMPPackets() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    int result = icmpPackets;
    sync->unlockStatistics();
    return result;
}

int PacketStatistics::getARPPackets() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();
    int result = arpPackets;
    sync->unlockStatistics();
    return result;
}

void PacketStatistics::printStatistics() {
    SynchronizationManager* sync = SynchronizationManager::getInstance();
    sync->lockStatistics();

    std::cout << "\n===== Statistics =====\n";
    std::cout << "Total: " << totalPackets << "\n";
    std::cout << "IPv4: " << ipv4Packets << "\n";
    std::cout << "TCP: " << tcpPackets << "\n";
    std::cout << "UDP: " << udpPackets << "\n";
    std::cout << "ICMP: " << icmpPackets << "\n";
    std::cout << "ARP: " << arpPackets << "\n";
    std::cout << "======================\n";

    sync->unlockStatistics();
}
