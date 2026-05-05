#include "PacketStatistics.h"
#include <iostream>

int PacketStatistics::totalPackets = 0;
int PacketStatistics::ipv4Packets = 0;
int PacketStatistics::tcpPackets = 0;
int PacketStatistics::udpPackets = 0;
int PacketStatistics::icmpPackets = 0;
int PacketStatistics::arpPackets = 0;

void PacketStatistics::incrementTotal() { totalPackets++; }
void PacketStatistics::incrementIPv4() { ipv4Packets++; }
void PacketStatistics::incrementTCP() { tcpPackets++; }
void PacketStatistics::incrementUDP() { udpPackets++; }
void PacketStatistics::incrementICMP() { icmpPackets++; }
void PacketStatistics::incrementARP() { arpPackets++; }

int PacketStatistics::getTotalPackets() { return totalPackets; }
int PacketStatistics::getIPv4Packets() { return ipv4Packets; }
int PacketStatistics::getTCPPackets() { return tcpPackets; }
int PacketStatistics::getUDPPackets() { return udpPackets; }
int PacketStatistics::getICMPPackets() { return icmpPackets; }
int PacketStatistics::getARPPackets() { return arpPackets; }

void PacketStatistics::printStatistics() {
    std::cout << "\n===== Statistics =====\n";
    std::cout << "Total: " << totalPackets << "\n";
    std::cout << "IPv4: " << ipv4Packets << "\n";
    std::cout << "TCP: " << tcpPackets << "\n";
    std::cout << "UDP: " << udpPackets << "\n";
    std::cout << "ICMP: " << icmpPackets << "\n";
    std::cout << "ARP: " << arpPackets << "\n";
    std::cout << "======================\n";
}
