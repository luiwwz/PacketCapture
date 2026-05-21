#include "IDSDetector.h"
#include <ctime>
#include <iostream>

IDSDetector::IDSDetector()
    : HIGH_PACKET_RATE_THRESHOLD(10),
      PORT_SCAN_THRESHOLD(10),
      TIME_WINDOW(60) {}

std::unique_ptr<AlertData> IDSDetector::detectThreats(const PacketData& packet) {
    std::lock_guard<std::mutex> lock(ids_mutex);

    std::string src_ip(packet.src_ip);

   //if (src_ip == "172.24.165.251") return nullptr;

    if (isHighPacketRate(src_ip)) {
        auto alert = std::make_unique<AlertData>();
        alert->source_ip   = src_ip;
        alert->dest_ip     = packet.dst_ip;
        alert->protocol    = packet.protocol;
        alert->alert_type  = "HIGH_PACKET_RATE";
        alert->description = "High packet rate detected from source IP";
        alert->timestamp   = time(nullptr);
        return alert;
    }

    if (packet.protocol == 6 && isPortScanAttempt(src_ip, packet.dst_port)) {
        auto alert = std::make_unique<AlertData>();
        alert->source_ip   = src_ip;
        alert->dest_ip     = packet.dst_ip;
        alert->source_port = packet.src_port;
        alert->dest_port   = packet.dst_port;
        alert->protocol    = packet.protocol;
        alert->alert_type  = "PORT_SCAN";
        alert->description = "Possible port scanning attempt detected";
        alert->timestamp   = time(nullptr);
        return alert;
    }

    return nullptr;
}

bool IDSDetector::isHighPacketRate(const std::string& ip) {
    time_t now = time(nullptr);

    if (ip_last_alert.count(ip) &&
        (now - ip_last_alert[ip]) > TIME_WINDOW) {
        ip_packet_count[ip] = 0;
        ip_last_reset[ip] = now;
	ip_last_alert.erase(ip);
    }

    if (!ip_last_alert.count(ip)) {
        if (ip_last_reset.find(ip) == ip_last_reset.end() ||
            (now - ip_last_reset[ip]) > TIME_WINDOW) {
            ip_packet_count[ip] = 0;
            ip_last_reset[ip] = now;
        }
    }

    ip_packet_count[ip]++;

    if (ip_packet_count[ip] > HIGH_PACKET_RATE_THRESHOLD) {
        if (!ip_last_alert.count(ip) ||
            (now - ip_last_alert[ip]) > TIME_WINDOW) {
            ip_last_alert[ip] = now;   
            ip_packet_count[ip] = 0; 
            return true;
        }
        return false;
    }
    return false;
}

bool IDSDetector::isPortScanAttempt(const std::string& src_ip, uint16_t dst_port) {
    time_t now = time(nullptr);

    if (port_scan_last_alert.count(src_ip) &&
        (now - port_scan_last_alert[src_ip]) > TIME_WINDOW) {
        port_scan_attempts[src_ip].clear();
        port_scan_last_alert.erase(src_ip);
    }

    port_scan_attempts[src_ip].insert(dst_port);

    if ((int)port_scan_attempts[src_ip].size() > PORT_SCAN_THRESHOLD) {
        if (!port_scan_last_alert.count(src_ip) ||
            (now - port_scan_last_alert[src_ip]) > TIME_WINDOW) {
            port_scan_last_alert[src_ip] = now;
            port_scan_attempts[src_ip].clear();
            return true;
        }
        return false;
    }
    return false;
}

void IDSDetector::resetStatistics() {
    std::lock_guard<std::mutex> lock(ids_mutex);
    ip_packet_count.clear();
    ip_last_reset.clear();
    port_scan_attempts.clear();
    ip_last_alert.clear();
    port_scan_last_alert.clear();
}
