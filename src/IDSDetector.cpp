#include "IDSDetector.h"
#include <ctime>
#include <iostream>

IDSDetector::IDSDetector()
    : HIGH_PACKET_RATE_THRESHOLD(10),
      PORT_SCAN_THRESHOLD(10),
      TIME_WINDOW(60) {}

AlertData* IDSDetector::detectThreats(const PacketData& packet) {
    std::string src_ip(packet.src_ip);

    if (isHighPacketRate(src_ip)) {
        AlertData* alert = new AlertData();
        alert->source_ip = src_ip;
        alert->dest_ip = packet.dst_ip;
        alert->protocol = packet.protocol;
        alert->alert_type = "HIGH_PACKET_RATE";
        alert->description = "High packet rate detected from source IP";
        alert->timestamp = time(nullptr);
        return alert;
    }

    if (packet.protocol == 6 && isPortScanAttempt(src_ip, packet.dst_port)) {
        AlertData* alert = new AlertData();
        alert->source_ip = src_ip;
        alert->dest_ip = packet.dst_ip;
        alert->source_port = packet.src_port;
        alert->dest_port = packet.dst_port;
        alert->protocol = packet.protocol;
        alert->alert_type = "PORT_SCAN";
        alert->description = "Possible port scanning attempt detected";
        alert->timestamp = time(nullptr);
        return alert;
    }

    return nullptr;
}

bool IDSDetector::isHighPacketRate(const std::string& ip) {
    time_t current_time = time(nullptr);

    if (ip_last_reset.find(ip) == ip_last_reset.end() || 
        (current_time - ip_last_reset[ip]) > TIME_WINDOW) {
        ip_packet_count[ip] = 0;
        ip_last_reset[ip] = current_time;
    }

    ip_packet_count[ip]++;

    return ip_packet_count[ip] > HIGH_PACKET_RATE_THRESHOLD;
}

bool IDSDetector::isPortScanAttempt(const std::string& src_ip, uint16_t dst_port) {
    if (port_scan_attempts.find(src_ip) == port_scan_attempts.end()) {
        port_scan_attempts[src_ip] = 0;
    }

    port_scan_attempts[src_ip]++;

    return port_scan_attempts[src_ip] > PORT_SCAN_THRESHOLD;
}

bool IDSDetector::isSuspiciousTCPFlags(uint8_t tcp_flags) {
    uint8_t SYN_FIN = 0x02 | 0x01;
    uint8_t SYN_RST = 0x02 | 0x04;
    uint8_t FIN_RST = 0x01 | 0x04;

    if ((tcp_flags & SYN_FIN) == SYN_FIN) return true;
    if ((tcp_flags & SYN_RST) == SYN_RST) return true;
    if ((tcp_flags & FIN_RST) == FIN_RST) return true;

    return false;
}

void IDSDetector::resetStatistics() {
    ip_packet_count.clear();
    ip_last_reset.clear();
    port_scan_attempts.clear();
}
