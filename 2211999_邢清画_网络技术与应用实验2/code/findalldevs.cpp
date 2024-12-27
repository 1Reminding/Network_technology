#include <pcap.h>
#include <stdio.h>

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // ��ȡ�������е��豸�б�
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // ����豸�б�
    printf("Available devices:\n");
    for (device = alldevs; device != NULL; device = device->next) {
        printf("%s - %s\n", device->name, device->description ? device->description : "No description available");
    }

    // �ͷ��豸�б�
    pcap_freealldevs(alldevs);
    return 0;
}