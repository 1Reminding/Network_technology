#define WIN32
#define HAVE_REMOTE
#include "pcap.h"
#include <iostream>
#include <WinSock2.h>
#include <chrono>
#include <thread>
using namespace std;
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#pragma pack(1)
typedef struct Frame_Header//֡�ײ�
{
    BYTE DesMAC[6];  //Ŀ�ĵ�ַ
    BYTE SrcMAC[6];  //Դ��ַ
    WORD FrameType;  //֡����
};
typedef struct ARP_Frame//ARP����
{
    Frame_Header FrameHeader;
    WORD HardwareType; //Ӳ������
    WORD ProtocolType; //Э������
    BYTE HLen; //Ӳ������
    BYTE PLen; //Э�鳤��
    WORD op; //��������
    BYTE SrcMAC[6]; //ԴMAC��ַ
    DWORD SrcIP; //ԴIP��ַ
    BYTE DesMAC[6]; //Ŀ��MAC��ַ
    DWORD DesIP; //Ŀ��IP��ַ
};

void* getaddress(struct sockaddr* sa)//�õ���Ӧ��IP��ַ
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);//IPV4��ַ
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);//IPV6��ַ
}
int main() {
    unsigned char mac[6]; // �洢���񵽵�MAC��ַ

    // ��������ԴIP��ԴMAC��ַ
    const char* virtualSrcIP = "192.168.1.1"; // ����ԴIP��ַ
    const unsigned char virtualSrcMAC[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }; // ����ԴMAC��ַ

    /*��ȡ�豸�б���ӡ��Ϣ*/
    pcap_if_t* d; //�����õ�ָ��
    pcap_addr_t* a; //��ַָ��
    pcap_if_t* devices; //ָ���豸�б��һ��
    int i = 0; //ͳ���豸����
    char errbuf[PCAP_ERRBUF_SIZE]; //������Ϣ������
    //���������Ϣ
    if (pcap_findalldevs(&devices, errbuf) == -1)
    {
        cout << stderr << "�����豸ʧ��: " << errbuf << endl;
        return 0;
    }
    //��ӡ�豸��Ϣ
     //��ӡ�豸�б����豸��Ϣ
    pcap_if_t* count; //�����õ�ָ��
    char srcip[INET_ADDRSTRLEN];//����ip
    //����豸����������Ϣ
    for (count = devices; count; count = count->next)//����countָ��ӵ�һ���豸��ʼ���ʵ����һ���豸
    {
        cout << ++i << ". " << count->name;//����豸��Ϣ������
        if (count->description) {
            cout << "������(" << count->description << ")" << endl;
        }
        for (a = count->addresses; a != NULL; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                char str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, getaddress((struct sockaddr*)a->addr), str, sizeof(str));//�� a->addr ǿ��ת��Ϊ struct sockaddr_in ���͵�ָ�룬������ sin_addr ��Ա�����а����� IPv4 ��ַ��
                cout << "IP��ַ��" << str << endl;
                inet_ntop(AF_INET, getaddress((struct sockaddr*)a->netmask), str, sizeof(str)); //�� a->netmask ǿ��ת��Ϊ struct sockaddr_in ���͵�ָ�룬��a->netmask����ṹ����ȡ�������롣
                cout << "�������룺" << str << endl;
                inet_ntop(AF_INET, getaddress((struct sockaddr*)a->broadaddr), str, sizeof(str));//�� a->netmask ǿ��ת��Ϊ struct sockaddr_in ���͵�ָ�룬��a->broadaddr����ṹ����ȡ�㲥��ַ��
                cout << "�㲥��ַ��" << str << endl;
                cout << "----------------------------------------------" << endl;
            }
        }
    }
    //�豸����Ϊ0
    if (i == 0) {
        cout << endl << "���ڴ����޲����豸��" << endl;
        return 0;
    }
    cout << "----------------------------------------------" << endl;
    /*ѡ���豸��������*/
    pcap_if_t* count2; //�����õ�ָ��2
    int num = 0;
    cout << "���뵱ǰҪ���ӵ�������ţ�";
    cin >> num;
    while (num < 1 || num>11) {
        cout << "����������������Ƿ���ȷ��" << endl;
        cout << "�������뵱ǰҪ���ӵ�������ţ�";
        cin >> num;
    }
    count2 = devices;
    for (int i = 1; i < num; i++) {//ѭ������ָ��ѡ��ڼ�������
        count2 = count2->next;
    }
    inet_ntop(AF_INET, getaddress((struct sockaddr*)count2->addresses->addr), srcip, sizeof(srcip));
    //�� a->addr ǿ��ת��Ϊ struct sockaddr_in ���͵�ָ�룬������ sin_addr ��Ա�����а����� IPv4 ��ַ��
    cout << "��ǰ�����豸�ӿڿ�IPΪ: " << srcip << endl << "��ǰ�����豸�ӿڿ�����Ϊ: " << count2->name << endl;
    //������ӿ�
    //ָ����ȡ���ݰ���󳤶�Ϊ65536,����ȷ���������ץ���������ݰ�
    //ָ��ʱ�䷶ΧΪ200ms
    pcap_t* point = pcap_open(count2->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 200, NULL, errbuf);
    if (point == NULL) {
        cout << "�򿪵�ǰ����ӿ�ʧ��" << endl;  //�򿪵�ǰ����ӿ�ʧ��
        pcap_freealldevs(devices);
        return 0;
    }
    else {
        cout << "�򿪵�ǰ����ӿڳɹ�����" << endl;
    }
     ARP_Frame send_ARPFrame;
    //��ȡ������MAC��ַ
    // ��װ����
    // ����ARP����
    for (int i = 0; i < 6; i++) {
        send_ARPFrame.FrameHeader.DesMAC[i] = 0xFF; // Ŀ��MAC����Ϊ�㲥��ַ
        send_ARPFrame.FrameHeader.SrcMAC[i] = virtualSrcMAC[i]; // ����ԴMAC��ַ
        send_ARPFrame.SrcMAC[i] = virtualSrcMAC[i]; // ����ԴMAC��ַ
        send_ARPFrame.DesMAC[i] = 0x00; // Ŀ��MAC��ַδ֪
    }
    send_ARPFrame.FrameHeader.FrameType = htons(0x0806); // ARP֡����
    send_ARPFrame.HardwareType = htons(0x0001); // Ӳ������Ϊ��̫��
    send_ARPFrame.ProtocolType = htons(0x0800); // Э������ΪIPv4
    send_ARPFrame.HLen = 6; // Ӳ����ַ����
    send_ARPFrame.PLen = 4; // Э���ַ����
    send_ARPFrame.op = htons(0x0001); // ����ΪARP����
    send_ARPFrame.SrcIP = inet_addr(virtualSrcIP); // ����ԴIP��ַ
    send_ARPFrame.DesIP = inet_addr(srcip); // ����Ŀ��IP��ַ������ʵ��Ŀ���޸ģ�


    struct pcap_pkthdr* pkt_header;
    const u_char* packetData;

    // �������ȴ�ʱ�䣨��λ�����룩
    const int MAX_WAIT_TIME_MS = 5000; // �ȴ�ʱ��Ϊ5��

    int ret;
    bool responseReceived = false; // ��־��������ʾ�Ƿ���յ���Ӧ
    auto startTime = std::chrono::steady_clock::now(); // ��ȡ��ǰʱ����Ϊ��ʼʱ��

    // ����һ��ARP����
    cout << "������...";
    pcap_sendpacket(point, (u_char*)&send_ARPFrame, sizeof(ARP_Frame));

    // ���趨ʱ���ڲ�����Ӧ
    while (true) {
        ret = pcap_next_ex(point, &pkt_header, &packetData);

        if (ret > 0) { // �������ݰ�
            // �ж��Ƿ�ΪARP��Ӧ��
            if (*(unsigned short*)(packetData + 12) == htons(0x0806) && // ֡����ΪARP
                *(unsigned short*)(packetData + 20) == htons(0x0002)) { // ��������ΪARP��Ӧ
                cout << endl;
                cout << "-----------------------------------------------" << endl;
                cout << "ARP���ݰ����ݣ�" << endl;

                // ��ӡ����ԴIP��ַ
                cout << "ԴIP��ַ:\t " << virtualSrcIP << endl;

                // ��ӡ����ԴMAC��ַ
                cout << "ԴMAC��ַ:\t ";
                for (int i = 0; i < 6; ++i) {
                    printf("%02X", virtualSrcMAC[i]);
                    if (i < 5) cout << "-";
                }
                cout << endl;

                // ��ӡĿ��IP��ַ
                cout << "Ŀ��IP��ַ:\t ";
                for (int i = 28; i < 32; ++i) {
                    printf("%d", packetData[i]);
                    if (i < 31) cout << ".";
                }
                cout << endl;

                // ��ȡĿ��MAC��ַ����6�ֽڣ�
                cout << "Ŀ��MAC��ַ:\t ";
                for (int i = 6; i < 12; ++i) {
                    printf("%02X", packetData[i]);
                    if (i < 11) cout << "-";
                }
                cout << endl;

                // ��mac�����¼������MAC��ַ
                for (int i = 0; i < 6; i++) {
                    mac[i] = *(unsigned char*)(packetData + 22 + i);
                }

                cout << "��ȡMAC��ַ�ɹ���MAC��ַΪ��";
                for (int i = 6; i < 12; ++i) {
                    printf("%02X", packetData[i]);
                    if (i < 11) cout << "-";
                }
                cout << endl;
                cout << "----------------------------------------------" << endl;

                responseReceived = true; // ���ñ�־Ϊtrue����ʾ�ѽ��յ���Ӧ
                break;
            }
        }

        // ����Ƿ񳬹����ȴ�ʱ��
        auto currentTime = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count() > MAX_WAIT_TIME_MS) {
            break; // �������ȴ�ʱ�䣬�˳�ѭ��
        }

        // �ȴ�����ʱ���Խ���CPUռ��
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // ����Ƿ���յ�ARP��Ӧ
    if (!responseReceived) {
        cout << endl;
        cout << "δ�ܽ��յ�ARP��Ӧ��������Ŀ��IP���������á�" << endl;
    }

    //���������Ϣ
    if (ret == -1) {  //���ù��̷�������
        cout << "�������ݰ�����" << endl;
        pcap_freealldevs(devices);
        return 0;
    }

    ARP_Frame rev_ARPFrame;
    /*��ȡĿ��������MAC��ַ*/
    for (int i = 0; i < 6; i++) {
        rev_ARPFrame.FrameHeader.DesMAC[i] = 0xff; //�㲥��ַ
        rev_ARPFrame.FrameHeader.SrcMAC[i] = mac[i]; //����MAC��ַ
        rev_ARPFrame.DesMAC[i] = 0x00; //����Ϊ0
        rev_ARPFrame.SrcMAC[i] = mac[i]; //����MAC��ַ
    }
    rev_ARPFrame.FrameHeader.FrameType = htons(0x0806);
    rev_ARPFrame.HardwareType = htons(0x0001);
    rev_ARPFrame.ProtocolType = htons(0x0800);
    rev_ARPFrame.HLen = 6;
    rev_ARPFrame.PLen = 4;
    rev_ARPFrame.op = htons(0x0001);
    rev_ARPFrame.SrcIP = inet_addr(srcip);
    cout << "������Ŀ��IP��ַ��";
    char ip[INET_ADDRSTRLEN];
    cin >> ip;

    rev_ARPFrame.DesIP = inet_addr(ip);
    int retryCount = 0; // ���Լ�����
    const int MAX_RETRIES =3; // ������Դ���

    while (retryCount < MAX_RETRIES) {
        // ���� ARP ����
        pcap_sendpacket(point, (u_char*)&rev_ARPFrame, sizeof(ARP_Frame));
        cout << "�ѷ��͵� " << (retryCount + 1) << " �� ARP ����..." << endl;

        // ���趨ʱ���ڲ�����Ӧ
        auto startTime = std::chrono::steady_clock::now();
        bool packetCaptured = false;

        while (true) {
            ret = pcap_next_ex(point, &pkt_header, &packetData);
            if (ret > 0) {
                // �ж��Ƿ�ΪĿ��� ARP ��Ӧ��
                if (*(unsigned short*)(packetData + 12) == htons(0x0806) //֡����ΪARP��htons(0x0806)��
                && *(unsigned short*)(packetData + 20) == htons(0x0002) //��������ΪARP��Ӧ��htons(0x0002)��
                && *(unsigned long*)(packetData + 28) == rev_ARPFrame.DesIP)//ip��ַΪ�����Ŀ��IP��ַ
            {
                cout << endl;
                cout << "-----------------------------------------------" << endl;
                cout << "ARP���ݰ����ݣ�" << endl;
                //��ӡ���ݰ�
                cout << "ԴIP��ַ:\t ";
                for (int i = 38; i < 42; ++i) {
                    printf("%d", packetData[i]);
                    if (i < 41) cout << ".";
                }
                cout << endl;
                // ��ȡMAC��ַ��0-6�ֽڣ�
                cout << "ԴMAC��ַ:\t ";
                for (int i = 0; i < 6; ++i) {
                    printf("%02X", packetData[i]);
                    if (i < 5) cout << "-";
                }
                cout << endl;
                cout << "Ŀ��IP��ַ:\t ";
                for (int i = 28; i < 32; ++i) {
                    printf("%d", packetData[i]);
                    if (i < 31) cout << ".";
                }
                cout << endl;
                // ��ȡĿ��MAC��ַ����6�ֽڣ�
                cout << "Ŀ��MAC��ַ:\t ";

                for (int i = 6; i < 12; ++i) {
                    printf("%02X", packetData[i]);
                    if (i < 11) cout << "-";
                }
                cout << endl;
                cout << "��ȡMAC��ַ�ɹ���MAC��ַΪ��";
                for (int i = 6; i < 12; ++i) {
                    printf("%02X", packetData[i]);
                    if (i < 11) cout << "-";
                }
                cout << endl;
                cout << "----------------------------------------------" << endl;
                break;
            }
        }
            // ��鳬ʱ
            auto currentTime = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count() > MAX_WAIT_TIME_MS) {
                break; // ��ʱ�˳�����ѭ��
            }

            // ���� CPU ռ��
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (packetCaptured) {
            break; // �ɹ����յ���Ӧ���˳���ѭ��
        }

        retryCount++;
        std::this_thread::sleep_for(std::chrono::seconds(1)); // ÿ������֮��ȴ� 1 ��
    }

    if (!responseReceived) {
        cout << "Ŀ������δ��Ӧ�������������Ӻ� IP ��ַ�Ƿ���ȷ��" << endl;
    }
        //���������Ϣ
        if (ret == -1) {  //���ù��̷�������
            cout << "�������ݰ�����" << endl;
            pcap_freealldevs(devices);
            return 0;
        }
        // �ر��豸
        pcap_close(point);
        pcap_freealldevs(devices);
        return 0;
    }
