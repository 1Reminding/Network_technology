#include <pcap.h>
#include <stdio.h>

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

    printf("Device %s opened for capturing\n", device->name);

    // �ͷ��豸�б�
    pcap_freealldevs(alldevs);
    return 0;
}
