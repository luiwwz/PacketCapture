#ifndef PACKET_STATISTICS_H
#define PACKET_STATISTICS_H

#include <atomic>

class PacketStatistics {
private:
    static std::atomic<int> totalPackets;
    static std::atomic<int> ipv4Packets;
    static std::atomic<int> tcpPackets;
    static std::atomic<int> udpPackets;
    static std::atomic<int> icmpPackets;
    static std::atomic<int> arpPackets;

public:
    static void incrementTotal();
    static void incrementIPv4();
    static void incrementTCP();
    static void incrementUDP();
    static void incrementICMP();
    static void incrementARP();

    static void printStatistics();

    static int getTotalPackets();
    static int getIPv4Packets();
    static int getTCPPackets();
    static int getUDPPackets();
    static int getICMPPackets();
    static int getARPPackets();
};

#endif
