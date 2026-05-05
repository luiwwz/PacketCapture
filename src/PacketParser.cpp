#include "PacketParser.h"
#include "PacketStatistics.h"
#include "PacketLogger.h"
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sstream>

std::string PacketParser::parseIPv4Packet(const u_char* packet, int packetSize, bool isLoopback) {
    PacketStatistics::incrementIPv4();

    const struct ip* ip_header = isLoopback ?
        reinterpret_cast<const struct ip*>(packet) :
        reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));

    std::ostringstream oss;

    oss << (isLoopback ? "Loopback IPv4\n" : "IPv4\n")
        << "Source IP: " << inet_ntoa(ip_header->ip_src) << "\n"
        << "Destination IP: " << inet_ntoa(ip_header->ip_dst) << "\n";

    switch (ip_header->ip_p) {
    case IPPROTO_TCP:
        oss << PacketParser::parseTCPProtocol(packet, packetSize, ip_header, isLoopback);
        break;
    case IPPROTO_UDP:
        oss << PacketParser::parseUDPProtocol(packet, packetSize, ip_header, isLoopback);
        break;
    case IPPROTO_ICMP:
        oss << PacketParser::parseICMPProtocol(packet, packetSize, ip_header, isLoopback);
        break;
    default:
        oss << "Other protocol\n";
        break;
    }

    return oss.str();
}

std::string PacketParser::parseTCPProtocol(const u_char* packet, int packetSize, const struct ip* ip_header, bool isLoopback) {
    PacketStatistics::incrementTCP();

    int ip_header_len = ip_header->ip_hl * 4;

    int offset = isLoopback ? ip_header_len : sizeof(struct ether_header) + ip_header_len;
    
    const struct tcphdr* tcp_header =
        reinterpret_cast<const struct tcphdr*>(packet + offset);

    std::ostringstream oss;

    oss << "Protocol: TCP\n"
        << "Source Port: " << ntohs(tcp_header->source) << "\n"
        << "Destination Port: " << ntohs(tcp_header->dest) << "\n";

    return oss.str();
}

std::string PacketParser::parseUDPProtocol(const u_char* packet, int packetSize, const struct ip* ip_header, bool isLoopback) {
    PacketStatistics::incrementUDP();

    int ip_header_len = ip_header->ip_hl * 4;

    int offset = isLoopback ? ip_header_len : sizeof(struct ether_header) + ip_header_len;
    
    const struct udphdr* udp_header =
        reinterpret_cast<const struct udphdr*>(packet + offset);

    std::ostringstream oss;

    oss << "Protocol: UDP\n"
        << "Source Port: " << ntohs(udp_header->source) << "\n"
        << "Destination Port: " << ntohs(udp_header->dest) << "\n";

    return oss.str();
}

std::string PacketParser::parseICMPProtocol(const u_char* packet, int packetSize, const struct ip* ip_header, bool isLoopback) {
    PacketStatistics::incrementICMP();

    int ip_header_len = ip_header->ip_hl * 4;

    int offset = isLoopback ? ip_header_len : sizeof(struct ether_header) + ip_header_len;
    
    const struct icmphdr* icmp_header =
        reinterpret_cast<const struct icmphdr*>(packet + offset);

    std::ostringstream oss;

    oss << "Protocol: ICMP\n";

    if (icmp_header->type == 8)
        oss << "ICMP Echo Request\n";
    else if (icmp_header->type == 0)
        oss << "ICMP Echo Reply\n";
    else if (icmp_header->type == 3)
        oss << "ICMP Destination unreachable\n";
    else if (icmp_header->type == 11)
        oss << "ICMP TTL exceeded\n";
    else
        oss << "Other ICMP\n";

    return oss.str();
}

std::string PacketParser::parseARPPacket(const u_char* packet, int packetSize) {
    PacketStatistics::incrementARP();

    const struct ether_arp* arp_header =
        reinterpret_cast<const struct ether_arp*>(packet + sizeof(struct ether_header));

    std::ostringstream oss;

    oss << "ARP\n"
        << "Source IP: "
        << inet_ntoa(*(struct in_addr*)arp_header->arp_spa) << "\n"
        << "Destination IP: "
        << inet_ntoa(*(struct in_addr*)arp_header->arp_tpa) << "\n";

    int op = ntohs(arp_header->ea_hdr.ar_op);

    if (op == ARPOP_REQUEST)
        oss << "ARP Request\n";
    else if (op == ARPOP_REPLY)
        oss << "ARP Reply\n";

    return oss.str();
}
