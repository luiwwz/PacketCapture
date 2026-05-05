#ifndef PACKET_STATISTICS_H
#define PACKET_STATISTICS_H

class PacketStatistics {
private:
    static int totalPackets;
    static int ipv4Packets;
    static int tcpPackets;
    static int udpPackets;
    static int icmpPackets;
    static int arpPackets;

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
