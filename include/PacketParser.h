#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <string>
#include <pcap.h>

class PacketParser {
public:
    static std::string parseIPv4Packet(const u_char* packet, int packetSize, bool isLoopback);
    static std::string parseARPPacket(const u_char* packet, int packetSize);
    
private:
    static std::string parseTCPProtocol(const u_char* packet, int packetSize, 
		                        const struct ip* ip_header, bool isLoopback);
    static std::string parseUDPProtocol(const u_char* packet, int packetSize, 
		                        const struct ip* ip_header, bool isLoopback);
    static std::string parseICMPProtocol(const u_char* packet, int packetSize, 
		                        const struct ip* ip_header, bool isLoopback);
};

#endif
