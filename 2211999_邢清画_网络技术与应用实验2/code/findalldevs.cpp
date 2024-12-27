#include <pcap.h>
#include <stdio.h>

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取本地所有的设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // 输出设备列表
    printf("Available devices:\n");
    for (device = alldevs; device != NULL; device = device->next) {
        printf("%s - %s\n", device->name, device->description ? device->description : "No description available");
    }

    // 释放设备列表
    pcap_freealldevs(alldevs);
    return 0;
}