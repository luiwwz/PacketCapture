#ifndef PACKETCAPTURER_H
#define PACKETCAPTURER_H

#include <string>
#include <pcap.h>

class PacketCapturer {
private:
      std::string interface;
      static void PacketHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);      
public:
      explicit PacketCapturer(const std::string& interface_);
      void startCapture();
};

#endif
