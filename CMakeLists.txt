cmake_minimum_required(VERSION 3.10)
project(PacketCapturer)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(include)

add_executable(PacketCapturer
    src/main.cpp
    src/Menu.cpp
    src/PacketCapturer.cpp
    src/PacketLogger.cpp
    src/PacketStatistics.cpp
    src/PacketParser.cpp
)

target_include_directories(PacketCapturer PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(PacketCapturer PRIVATE ${PCAP_LIBRARIES})
