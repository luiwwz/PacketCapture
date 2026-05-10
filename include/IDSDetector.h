#ifndef IDS_DETECTOR_H
#define IDS_DETECTOR_H

#include "RingBuffer.h"
#include <string>
#include <map>
#include <ctime>

struct AlertData {
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    uint8_t protocol;
    std::string alert_type;
    std::string description;
    time_t timestamp;
};

class IDSDetector {
private:
    std::map<std::string, int> ip_packet_count;
    std::map<std::string, long> ip_last_reset;
    std::map<std::string, int> port_scan_attempts;
    const int HIGH_PACKET_RATE_THRESHOLD;
    const int PORT_SCAN_THRESHOLD;
    const long TIME_WINDOW;

public:
    IDSDetector();
    AlertData* detectThreats(const PacketData& packet);
    bool isHighPacketRate(const std::string& ip);
    bool isPortScanAttempt(const std::string& src_ip, uint16_t dst_port);
    bool isSuspiciousTCPFlags(uint8_t tcp_flags);
    void resetStatistics();
};

#endif
