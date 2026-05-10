cmake_minimum_required(VERSION 3.10)
project(PacketCapturer)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

find_package(Threads REQUIRED)

include_directories(include)
include_directories(${SQLITE3_INCLUDE_DIRS})

add_executable(PacketCapturer
    src/main.cpp
    src/Menu.cpp
    src/PacketCapturer.cpp
    src/PacketLogger.cpp
    src/PacketStatistics.cpp
    src/PacketParser.cpp
    src/SynchronizationManager.cpp
    src/PacketBuffer.cpp
    src/IDSDetector.cpp
    src/DatabaseManager.cpp
    src/ProcessManager.cpp
)

target_include_directories(PacketCapturer PRIVATE ${PCAP_INCLUDE_DIRS} ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(PacketCapturer PRIVATE ${PCAP_LIBRARIES} ${SQLITE3_LIBRARIES} Threads::Threads)
