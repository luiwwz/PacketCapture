#include "PacketStatistics.h"
#include <iostream>

std::atomic<int> PacketStatistics::totalPackets(0);
std::atomic<int> PacketStatistics::ipv4Packets(0);
std::atomic<int> PacketStatistics::tcpPackets(0);
std::atomic<int> PacketStatistics::udpPackets(0);
std::atomic<int> PacketStatistics::icmpPackets(0);
std::atomic<int> PacketStatistics::arpPackets(0);

void PacketStatistics::incrementTotal()  { ++totalPackets; }
void PacketStatistics::incrementIPv4()   { ++ipv4Packets;  }
void PacketStatistics::incrementTCP()    { ++tcpPackets;   }
void PacketStatistics::incrementUDP()    { ++udpPackets;   }
void PacketStatistics::incrementICMP()   { ++icmpPackets;  }
void PacketStatistics::incrementARP()    { ++arpPackets;   }

int PacketStatistics::getTotalPackets()  { return totalPackets.load(); }
int PacketStatistics::getIPv4Packets()   { return ipv4Packets.load();  }
int PacketStatistics::getTCPPackets()    { return tcpPackets.load();   }
int PacketStatistics::getUDPPackets()    { return udpPackets.load();   }
int PacketStatistics::getICMPPackets()   { return icmpPackets.load();  }
int PacketStatistics::getARPPackets()    { return arpPackets.load();   }

void PacketStatistics::printStatistics() {
    std::cout << "\n===== Statistics =====\n"
              << "Total: " << totalPackets.load() << "\n"
              << "IPv4:  " << ipv4Packets.load()  << "\n"
              << "TCP:   " << tcpPackets.load()   << "\n"
              << "UDP:   " << udpPackets.load()   << "\n"
              << "ICMP:  " << icmpPackets.load()  << "\n"
              << "ARP:   " << arpPackets.load()   << "\n"
              << "======================\n";
}
