#include "PacketCapturer.h"
#include "PacketLogger.h"
#include "PacketStatistics.h"
#include "PacketParser.h"
#include "PacketBuffer.h"
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>

PacketCapturer::PacketCapturer(const std::string& interface_)
    : interface(interface_) {}

void PacketCapturer::startCapture(const std::string& ip, int protocolChoice, int packetCount) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cout << "Error opening device " << errbuf << std::endl;
        return;
    }

    std::string filter;

    if (ip != "0") {
        filter = "host " + ip;
    }

    switch (protocolChoice) {
        case 2: filter += (filter.empty() ? "tcp" : " and tcp"); break;
        case 3: filter += (filter.empty() ? "udp" : " and udp"); break;
        case 4: filter += (filter.empty() ? "icmp" : " and icmp"); break;
        case 5: filter += (filter.empty() ? "arp" : " and arp"); break;
        default: break;
    }

    if (!filter.empty()) {
        struct bpf_program fp;

        if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cout << "Filter compile error: " << pcap_geterr(handle) << std::endl;
            std::cout << "Filter string [" << filter << "]\n";
            return;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            std::cout << "Filter set error\n";
            return;
        }

        std::cout << "Filter: " << filter << std::endl;
    }

    std::cout << "Listening on interface " << interface << std::endl;

    if (packetCount > 0) {
        std::cout << "Waiting for " << packetCount << " packets... (Press Ctrl+C to stop)\n";
    } else {
        std::cout << "Waiting for packets... (Press Ctrl+C to stop)\n";
    }

    pcap_loop(handle, packetCount, PacketHandler, (u_char*)this);

    PacketLogger::closeLog();
    pcap_close(handle);
}

void PacketCapturer::PacketHandler(u_char* userData,
    const struct pcap_pkthdr* pkthdr,
    const u_char* packet) {

    PacketStatistics::incrementTotal();

    std::cout << PacketStatistics::getTotalPackets() << " Packet captured\n";

    std::ostringstream oss;

    oss << "Size: " << pkthdr->len << " bytes\n"
        << "Time: " << pkthdr->ts.tv_sec << "." << pkthdr->ts.tv_usec;

    PacketLogger::log(oss.str());

    const struct ether_header* eth_header =
    reinterpret_cast<const struct ether_header*>(packet);

    bool isLoopback = (ntohs(eth_header->ether_type) == 0);

    PacketBuffer* buffer = PacketBuffer::getInstance();
    PacketData packet_data;

    packet_data.length = pkthdr->len;
    packet_data.timestamp_sec = pkthdr->ts.tv_sec;
    packet_data.timestamp_usec = pkthdr->ts.tv_usec;

    if (isLoopback) {
        const u_char* loopback_packet = packet + 4;

        const struct ip* ip_header = reinterpret_cast<const struct ip*>(loopback_packet);

        strcpy(packet_data.src_ip, inet_ntoa(ip_header->ip_src));
        strcpy(packet_data.dst_ip, inet_ntoa(ip_header->ip_dst));
        packet_data.protocol = ip_header->ip_p;

        switch (ip_header->ip_p) {
        case IPPROTO_ICMP: {
            std::string info = PacketParser::parseIPv4Packet(loopback_packet, pkthdr->len - 4, true);
            PacketLogger::log(info);
            break;
        }
        case IPPROTO_TCP: {
            std::string info = PacketParser::parseIPv4Packet(loopback_packet, pkthdr->len - 4, true);
            PacketLogger::log(info);
            break;
        }
        case IPPROTO_UDP: {
            std::string info = PacketParser::parseIPv4Packet(loopback_packet, pkthdr->len - 4, true);
            PacketLogger::log(info);
            break;
        }
        }
    } else {
        const struct ether_header* eth_hdr =
            reinterpret_cast<const struct ether_header*>(packet);

        switch (ntohs(eth_hdr->ether_type)) {
        case 0x0800: {
            const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
            strcpy(packet_data.src_ip, inet_ntoa(ip_header->ip_src));
            strcpy(packet_data.dst_ip, inet_ntoa(ip_header->ip_dst));
            packet_data.protocol = ip_header->ip_p;

            std::string info = PacketParser::parseIPv4Packet(packet, pkthdr->len, false);
            PacketLogger::log(info);
            break;
        }

        case 0x0806: {
            std::string info = PacketParser::parseARPPacket(packet, pkthdr->len);
            PacketLogger::log(info);
            break;
        }
        }
    }

    buffer->addPacket(packet_data);
}
