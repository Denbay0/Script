// packet_capture.cpp

#include "packet_capture.h"
#include <iostream>
#include <fstream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <cstdlib>

const int PacketCapture::BLOCK_DURATION_MINUTES = 30; // Блокируем на 30 минут
const int PacketCapture::REQUEST_THRESHOLD = 50; // Порог количества запросов
const int PacketCapture::TIME_WINDOW_SECONDS = 10; // Временное окно 10 секунд

std::map<std::string, int> PacketCapture::ipCount;
std::map<std::string, std::chrono::steady_clock::time_point> PacketCapture::ipTimestamps;
std::set<std::string> PacketCapture::blockedIPs;
std::mutex PacketCapture::ipMutex;

PacketCapture::PacketCapture() {
    loadBlockedIPs();
}

void PacketCapture::startCapture() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;

    // Открываем сессию для перехвата на интерфейсе eth0 (замените на ваш интерфейс)
    descr = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (descr == nullptr) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        return;
    }

    // Запускаем поток для разблокировки IP
    std::thread unblockThread(unblockIPThread);
    unblockThread.detach();

    // Запускаем цикл перехвата пакетов
    if (pcap_loop(descr, 0, PacketCapture::packetHandler, nullptr) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(descr) << std::endl;
        return;
    }

    pcap_close(descr);
}

void PacketCapture::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    char sourceIp[INET_ADDRSTRLEN];

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) != ETHERTYPE_IP) {
        return; // Не IP-пакет
    }

    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);

    std::string srcIpStr(sourceIp);

    // Проверяем, заблокирован ли IP
    {
        std::lock_guard<std::mutex> lock(ipMutex);
        if (blockedIPs.find(srcIpStr) != blockedIPs.end()) {
            return; // IP заблокирован, игнорируем
        }
    }

    // Проверка на SYN-флуд
    if (isSynFlood(packet)) {
        blockIPAddress(srcIpStr);
        std::cout << "Обнаружен SYN-флуд. IP заблокирован: " << srcIpStr << std::endl;
        return;
    }

    auto now = std::chrono::steady_clock::now();

    // Обновляем счетчики запросов
    {
        std::lock_guard<std::mutex> lock(ipMutex);
        ipCount[srcIpStr]++;
        if (ipTimestamps.find(srcIpStr) == ipTimestamps.end()) {
            ipTimestamps[srcIpStr] = now;
        }
    }

    // Проверяем, прошло ли временное окно
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - ipTimestamps[srcIpStr]);
    if (duration.count() > TIME_WINDOW_SECONDS) {
        {
            std::lock_guard<std::mutex> lock(ipMutex);
            ipCount[srcIpStr] = 1;
            ipTimestamps[srcIpStr] = now;
        }
    }

    // Если количество запросов превышает порог за временное окно, блокируем IP
    if (ipCount[srcIpStr] > REQUEST_THRESHOLD) {
        blockIPAddress(srcIpStr);
        std::cout << "Частые запросы. IP заблокирован: " << srcIpStr << std::endl;
    }
}

bool PacketCapture::isSynFlood(const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    if (ipHeader->ip_p != IPPROTO_TCP) {
        return false; // Не TCP-пакет
    }

    const struct tcphdr* tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    // Проверяем, установлен ли SYN-флаг без ACK
    if (tcpHeader->syn && !tcpHeader->ack) {
        return true;
    }
    return false;
}

void PacketCapture::blockIPAddress(const std::string& ip) {
    {
        std::lock_guard<std::mutex> lock(ipMutex);
        if (blockedIPs.find(ip) != blockedIPs.end()) {
            return; // IP уже заблокирован
        }
    }


    std::string command = "sudo iptables -A INPUT -s " + ip + " -j DROP";
    int result = system(command.c_str());
    if (result != 0) {
        std::cerr << "Не удалось заблокировать IP: " << ip << std::endl;
    }
    else {
        std::cout << "IP успешно заблокирован: " << ip << std::endl;
        std::lock_guard<std::mutex> lock(ipMutex);
        blockedIPs.insert(ip);
        ipTimestamps[ip] = std::chrono::steady_clock::now();
        saveBlockedIPs();
    }
}

void PacketCapture::unblockIPAddress(const std::string& ip) {
    std::string command = "sudo iptables -D INPUT -s " + ip + " -j DROP";
    int result = system(command.c_str());
    if (result != 0) {
        std::cerr << "Не удалось разблокировать IP: " << ip << std::endl;
    }
    else {
        std::cout << "IP разблокирован: " << ip << std::endl;
    }
}

void PacketCapture::unblockIPThread() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(60)); // Проверяем каждые 60 секунд
        auto now = std::chrono::steady_clock::now();

        std::lock_guard<std::mutex> lock(ipMutex);
        for (auto it = blockedIPs.begin(); it != blockedIPs.end(); ) {
            // Проверяем, прошло ли время блокировки
            auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - ipTimestamps[*it]);
            if (duration.count() >= BLOCK_DURATION_MINUTES) {
                unblockIPAddress(*it);
                ipTimestamps.erase(*it);
                it = blockedIPs.erase(it);
                saveBlockedIPs();
            }
            else {
                ++it;
            }
        }
    }
}
void PacketCapture::loadBlockedIPs() {
    std::ifstream infile("blocked_ips.txt");
    if (!infile.is_open()) {
        return;
    }
    std::string ip;
    while (std::getline(infile, ip)) {
        if (!ip.empty()) {
            blockedIPs.insert(ip);
            ipTimestamps[ip] = std::chrono::steady_clock::now(); // Предполагаем, что блокировка началась сейчас
            // Восстанавливаем правило iptables
            std::string command = "sudo iptables -A INPUT -s " + ip + " -j DROP";
            system(command.c_str());
        }
    }
    infile.close();
}

void PacketCapture::saveBlockedIPs() {
    std::ofstream outfile("blocked_ips.txt");
    if (!outfile.is_open()) {
        std::cerr << "Не удалось сохранить блок-лист" << std::endl;
        return;
    }
    for (const auto& ip : blockedIPs) {
        outfile << ip << std::endl;
    }
    outfile.close();
}
