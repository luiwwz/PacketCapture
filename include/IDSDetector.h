#ifndef IDS_DETECTOR_H
#define IDS_DETECTOR_H

#include "PacketData.h"
#include <string>
#include <map>
#include <ctime>

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
