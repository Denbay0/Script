#pragma once 

#include <pcap.h>
#include <string>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>
#include <set>

class PacketCapture {
public:
    PacketCapture();
    void startCapture();
private:
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    static std::map<std::string, int> ipCount;
    static std::map<std::string, std::chrono::steady_clock::time_point> ipTimestamps;
    static std::set<std::string> blockedIPs;
    static std::mutex ipMutex;
    static void blockIPAddress(const std::string& ip);
    static void unblockIPAddress(const std::string& ip);
    static void unblockIPThread();
    static void loadBlockedIPs();
    static void saveBlockedIPs();
    static bool isSynFlood(const u_char* packet);
    static const int BLOCK_DURATION_MINUTES; // Время блокировки в минутах
    static const int REQUEST_THRESHOLD; // Порог количества запросов
    static const int TIME_WINDOW_SECONDS; // Временное окно в секундах
};
