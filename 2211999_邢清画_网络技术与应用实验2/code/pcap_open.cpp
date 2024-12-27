#include <pcap.h>
#include <stdio.h>

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // 打开第一个设备进行捕获
    device = alldevs;  // 假设选择第一个设备
    handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    printf("Device %s opened for capturing\n", device->name);

    // 释放设备列表
    pcap_freealldevs(alldevs);
    return 0;
}
