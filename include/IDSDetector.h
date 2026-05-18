#ifndef IDS_DETECTOR_H
#define IDS_DETECTOR_H

#include "PacketData.h"
#include <string>
#include <map>
#include <set>
#include <mutex>
#include <memory>  
#include <ctime>

class IDSDetector {
private:

    std::mutex ids_mutex;

    std::map<std::string, int>  ip_packet_count;
    std::map<std::string, long> ip_last_reset;

    std::map<std::string, std::set<uint16_t>> port_scan_attempts;
    std::map<std::string, time_t> ip_last_alert;

    const int  HIGH_PACKET_RATE_THRESHOLD;
    const int  PORT_SCAN_THRESHOLD;
    const long TIME_WINDOW;

    bool isHighPacketRate(const std::string& ip);
    bool isPortScanAttempt(const std::string& src_ip, uint16_t dst_port);

    IDSDetector();
    IDSDetector(const IDSDetector&) = delete;
    IDSDetector& operator=(const IDSDetector&) = delete;

public:

    static IDSDetector& getInstance() {
        static IDSDetector instance;
        return instance;
    }

    std::unique_ptr<AlertData> detectThreats(const PacketData& packet);
    void resetStatistics();
};

#endif
