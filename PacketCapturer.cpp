#include "PacketCapturer.h"
#include <iostream>
#include <netinet/ether.h>
#include <arpa/inet.h>

PacketCapturer::PacketCapturer(const std::string& interface_) 
	: interface(interface_) {}

void PacketCapturer::startCapture() {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

   if(handle == nullptr) {
      std::cout << "Error opening device " << errbuf << std::endl;
      return;
   } 

   std::cout << "Listening on interface  " << interface << std::endl;

   pcap_loop(handle, 0, PacketHandler, nullptr);

   pcap_close(handle);
}

void PacketCapturer::PacketHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
   const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(packet);

   std::cout << "Packet captured:\n";
   std::cout << "Size " << pkthdr->len << "bytes\n";
   std::cout << "Time " << pkthdr->ts.tv_sec << "." << pkthdr->ts.tv_usec << "\n";
}
