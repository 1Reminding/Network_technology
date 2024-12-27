#include <pcap.h>
#include <stdio.h>
#include <winsock2.h>  // ����ntohs����
#pragma comment(lib, "ws2_32.lib")  // ����Winsock��

// ������̫��֡ͷ�ṹ
struct ether_header {
    u_char ether_dhost[6]; // Ŀ��MAC��ַ
    u_char ether_shost[6]; // ԴMAC��ַ
    u_short ether_type;    // ����/�����ֶ�
};

void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header* eth_header;
    eth_header = (struct ether_header*)packet;

    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth_header->ether_shost[0],
        eth_header->ether_shost[1],
        eth_header->ether_shost[2],
        eth_header->ether_shost[3],
        eth_header->ether_shost[4],
        eth_header->ether_shost[5]);

    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth_header->ether_dhost[0],
        eth_header->ether_dhost[1],
        eth_header->ether_dhost[2],
        eth_header->ether_dhost[3],
        eth_header->ether_dhost[4],
        eth_header->ether_dhost[5]);

    printf("Type/Length: 0x%04x\n", ntohs(eth_header->ether_type));
}

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // ��ȡ�豸�б�
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // �򿪵�һ���豸���в���
    device = alldevs;  // ����ѡ���һ���豸
    handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    printf("Start capturing on device %s...\n", device->name);

    // ��ʼ�������ݰ�
    pcap_loop(handle, 10, packet_handler, NULL);  // ����10�����ݰ�

    // �ͷ��豸�б�
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}