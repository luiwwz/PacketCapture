# PacketCapture

A multiprocess packet capture and network traffic analysis toolkit written in C++ using `libpcap`.

The project captures and analyzes live network traffic, parses low-level protocols, collects statistics, and demonstrates concepts of packet sniffing, Linux networking, and interprocess communication.

This project was created for educational purposes in cybersecurity and computer networks.

---

## Features

- Live packet capture using `libpcap`
- Ethernet frame parsing
- IPv4 packet analysis
- ARP packet detection and parsing
- TCP / UDP / ICMP protocol analysis
- Packet statistics collection
- Packet logging system
- Traffic filtering
- Multiprocess architecture
- Modular OOP design
- Linux support

---

## Supported Protocols

The sniffer currently recognizes and analyzes:

- Ethernet
- ARP
- IPv4
- TCP
- UDP
- ICMP

---

## Technologies Used

- C++17
- `libpcap`
- CMake
- Linux networking APIs
- Object-Oriented Programming (OOP)
- Interprocess Communication (IPC)

---

## Project Structure

```text
PacketCapture/
│
├── include/
│   ├── DatabaseManager.h
│   ├── IDSDetector.h
│   ├── Menu.h
│   ├── PacketBuffer.h
│   ├── PacketCapturer.h
│   ├── PacketLogger.h
│   ├── PacketParser.h
│   ├── PacketStatistics.h
│   ├── ProcessManager.h
│   ├── RingBuffer.h
│   └── SynchronizationManager.h
│
├── src/
│   ├── DatabaseManager.cpp
│   ├── IDSDetector.cpp
│   ├── Menu.cpp
│   ├── PacketBuffer.cpp
│   ├── PacketCapturer.cpp
│   ├── PacketLogger.cpp
│   ├── PacketParser.cpp
│   ├── PacketStatistics.cpp
│   ├── ProcessManager.cpp
│   ├── SynchronizationManager.cpp
│   └── main.cpp
│
├── .gitignore
├── CMakeLists.txt
└── README.md
```

---

## How It Works

The application captures packets directly from a selected network interface using `libpcap`.

Each packet goes through several stages:

1. Packet capture
2. Protocol parsing
3. Traffic analysis
4. Logging
5. Statistics update

The project also demonstrates a multiprocess architecture:

- one process captures packets
- another process analyzes traffic and statistics

Processes communicate using shared memory / IPC mechanisms.

---

## ARP Packet Analysis

The sniffer supports ARP packet detection and parsing.

For ARP packets the application can display:

- Sender MAC address
- Sender IP address
- Target MAC address
- Target IP address
- ARP request/reply type

Example:

```text
[ARP] Request: Who has 192.168.1.1?
Sender MAC: 00:11:22:33:44:55
Sender IP : 192.168.1.10
```

---

## Installation

### Requirements

Install dependencies on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install libpcap-dev cmake g++
```

---

## Build

Clone the repository:

```bash
git clone https://github.com/luiwwz/PacketCapture.git
cd PacketCapture
```

Create build directory:

```bash
mkdir build
cd build
```

Compile the project:

```bash
cmake ..
make
```

---

## Run

Packet capturing requires root privileges on Linux.

```bash
sudo ./PacketCapture
```

---

## Example Output

```text
[TCP] 192.168.1.5:443 -> 192.168.1.10:51234

[UDP] 8.8.8.8:53 -> 192.168.1.10:53321

[ICMP] Echo Request

[ARP] Request: Who has 192.168.1.1?
```

---

## Learning Goals

This project was created to practice:

- Packet sniffing
- Network protocol analysis
- Linux system programming
- Multiprocessing
- Interprocess communication
- Low-level networking
- C++ OOP architecture
- Working with raw packets

---

## Future Improvements

- PCAP file export
- DNS parsing
- HTTP traffic analysis
- IPv6 support
- ncurses terminal UI
- Real-time traffic graphs
- Advanced packet filtering
- Multithreaded processing

---

## Security Notice

This project is intended only for educational and authorized network analysis purposes.

Do not use packet sniffing tools on networks without permission.

---

## References

- libpcap documentation: https://www.tcpdump.org/
- libpcap repository: https://github.com/the-tcpdump-group/libpcap

---
