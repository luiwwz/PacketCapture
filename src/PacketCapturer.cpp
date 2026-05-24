#include "PacketCapturer.h"
#include "PacketLogger.h"
#include "PacketStatistics.h"
#include "PacketParser.h"
#include "PacketBuffer.h"
#include <iostream>
#include <string>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>

#define SLL_HEADER_LEN 16
#define SLL_PROTO_OFFSET 14 

struct CaptureContext {
    PacketCapturer* capturer;
    int datalink_type;
};

PacketCapturer::PacketCapturer(const std::string& interface_)
    : interface(interface_) {}

void PacketCapturer::startCapture(const std::string& ip, int protocolChoice, int packetCount) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cout << "Error opening device " << errbuf << std::endl;
        return;
    }

    int datalink = pcap_datalink(handle);
    std::cout << "Datalink type: " << datalink << " ("
              << pcap_datalink_val_to_name(datalink) << ")\n";

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

    CaptureContext ctx{ this, datalink };
    pcap_loop(handle, packetCount, PacketHandler, (u_char*)&ctx);

    PacketLogger::closeLog();
    pcap_close(handle);
}

void PacketCapturer::PacketHandler(u_char* userData,
    const struct pcap_pkthdr* pkthdr,
    const u_char* packet) {

    CaptureContext* ctx = reinterpret_cast<CaptureContext*>(userData);
    int datalink = ctx->datalink_type;

    PacketStatistics::incrementTotal();
    std::cout << PacketStatistics::getTotalPackets() << " Packet captured\n";

    std::ostringstream oss;
    oss << "Size: " << pkthdr->len << " bytes\n"
        << "Time: " << pkthdr->ts.tv_sec << "." << pkthdr->ts.tv_usec;
    PacketLogger::log(oss.str());

    PacketData packet_data;
    packet_data.length        = pkthdr->len;
    packet_data.timestamp_sec  = pkthdr->ts.tv_sec;
    packet_data.timestamp_usec = pkthdr->ts.tv_usec;
  
    if (datalink == DLT_NULL) {
        const u_char* ip_start = packet + 4;
        const struct ip* ip_header = reinterpret_cast<const struct ip*>(ip_start);

        inet_ntop(AF_INET, &ip_header->ip_src, packet_data.src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->ip_dst, packet_data.dst_ip, INET_ADDRSTRLEN);
        packet_data.protocol = ip_header->ip_p;

        std::string info = PacketParser::parseIPv4Packet(ip_start, pkthdr->len - 4, true);
        PacketLogger::log(info);

    } else if (datalink == DLT_LINUX_SLL) {
        uint16_t ether_type = ntohs(*(uint16_t*)(packet + SLL_PROTO_OFFSET));
        const u_char* ip_start = packet + SLL_HEADER_LEN;

        if (ether_type == 0x0800) {  // IPv4
            const struct ip* ip_header = reinterpret_cast<const struct ip*>(ip_start);

            inet_ntop(AF_INET, &ip_header->ip_src, packet_data.src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_header->ip_dst, packet_data.dst_ip, INET_ADDRSTRLEN);
            packet_data.protocol = ip_header->ip_p;

            if (ip_header->ip_p == IPPROTO_TCP) {
                const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(
                    ip_start + ip_header->ip_hl * 4);
                packet_data.src_port = ntohs(tcp->source);
                packet_data.dst_port = ntohs(tcp->dest);
            } else if (ip_header->ip_p == IPPROTO_UDP) {
                const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(
                    ip_start + ip_header->ip_hl * 4);
                packet_data.src_port = ntohs(udp->source);
                packet_data.dst_port = ntohs(udp->dest);
            }

            std::string info = PacketParser::parseIPv4Packet(ip_start, pkthdr->len - SLL_HEADER_LEN, true);
            PacketLogger::log(info);

        } else if (ether_type == 0x0806) {  // ARP
            strncpy(packet_data.src_ip, "ARP", INET_ADDRSTRLEN);
            strncpy(packet_data.dst_ip, "ARP", INET_ADDRSTRLEN);
            // ARP поверх SLL — парсер ожидает ethernet, пропускаем
            PacketLogger::log("ARP (SLL)\n");
        }

     } else {
        const struct ether_header* eth_hdr =
            reinterpret_cast<const struct ether_header*>(packet);

        switch (ntohs(eth_hdr->ether_type)) {
        case 0x0800: {
            const struct ip* ip_header =
                reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));

            inet_ntop(AF_INET, &ip_header->ip_src, packet_data.src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_header->ip_dst, packet_data.dst_ip, INET_ADDRSTRLEN);
            packet_data.protocol = ip_header->ip_p;

            if (ip_header->ip_p == IPPROTO_TCP) {
                const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(
                    packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
                packet_data.src_port = ntohs(tcp->source);
                packet_data.dst_port = ntohs(tcp->dest);
            } else if (ip_header->ip_p == IPPROTO_UDP) {
                const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(
                    packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
                packet_data.src_port = ntohs(udp->source);
                packet_data.dst_port = ntohs(udp->dest);
            }

            std::string info = PacketParser::parseIPv4Packet(packet, pkthdr->len, false);
            PacketLogger::log(info);
            break;
        }

        case 0x0806: {
            strncpy(packet_data.src_ip, "ARP", INET_ADDRSTRLEN);
            strncpy(packet_data.dst_ip, "ARP", INET_ADDRSTRLEN);
            std::string info = PacketParser::parseARPPacket(packet, pkthdr->len);
            PacketLogger::log(info);
            break;
        }
        }
    }

    PacketBuffer::getInstance().addPacket(std::move(packet_data));
}
