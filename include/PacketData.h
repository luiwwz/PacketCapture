#ifndef PACKET_DATA_H
#define PACKET_DATA_H

#include <cstdint>
#include <vector>
#include <string>
#include <ctime>
#include <arpa/inet.h>   // INET_ADDRSTRLEN

struct PacketData {
    char src_ip[INET_ADDRSTRLEN] = {};   // use 'inet_ntop' instead of 'inet_ntoa'
    char dst_ip[INET_ADDRSTRLEN] = {};
    int src_port = 0;
    int dst_port = 0;
    int protocol = 0;
    int length = 0;
    uint32_t timestamp_sec = 0;
    uint32_t timestamp_usec = 0;

    std::vector<uint8_t> data;
};

struct AlertData {
    std::string source_ip;
    std::string dest_ip;
    int source_port = 0;
    int dest_port = 0;
    int protocol = 0;
    std::string alert_type;
    std::string description;

    time_t timestamp = 0;
};

#endif
