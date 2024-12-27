#include <iostream>
#include <pcap.h>
#pragma comment(lib,"ws2_32.lib")//否则 ntohs() 会导致编译失败。
#pragma warning( disable : 4996 )//要使用旧函数
using namespace std;

void* getaddress(struct sockaddr* sa)//得到对应的IP地址
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);//IPV4地址
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);//IPV6地址
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];//用于存储 libpcap 函数或操作出现问题时的错误消息或诊断信息。
    pcap_if_t* devices; //指向设备列表第一个
    // 获取网络接口设备列表,返回0表示正常，-1表示出错,输出errbuf里的错误信息并返回
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        cerr << "查找设备失败: " << errbuf << endl;
        return 0;
    }
    //打印设备列表中设备信息
    pcap_if_t* count; //遍历用的指针
    pcap_addr_t* a; //地址指针
    int i = 0;//设备数量计数
    //输出设备名和描述信息
    for (count = devices; count; count = count->next)//借助count指针从第一个设备开始访问到最后一个设备
    {
        cout << ++i << ". " << count->name;//输出设备信息和描述
        if (count->description)
            cout << "(" << count->description << ")" << endl;
        else
            cout << "(无描述!)" << endl;
        for (a = count->addresses; a != NULL; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                char str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, getaddress((struct sockaddr*)a->addr), str, sizeof(str));//将 a->addr 强制转换为 struct sockaddr_in 类型的指针，并访问 sin_addr 成员，其中包含了 IPv4 地址。
                cout << "IP地址：" << str << endl;
                inet_ntop(AF_INET, getaddress((struct sockaddr*)a->netmask), str, sizeof(str)); //将 a->netmask 强制转换为 struct sockaddr_in 类型的指针，从a->netmask这个结构中提取子网掩码。
                cout << "子网掩码：" << str << endl;
                inet_ntop(AF_INET, getaddress((struct sockaddr*)a->broadaddr), str, sizeof(str));//将 a->netmask 强制转换为 struct sockaddr_in 类型的指针，从a->broadaddr这个结构中提取广播地址。
                cout << "广播地址：" << str << endl;
            }
        }
    }
    //设备数量为0
    if (i == 0)
    {
        cout << endl << "存在错误！无查找设备！" << endl;
        return 0;
    }
    cout << "----------------------------------------------" << endl;

    // 开始捕获数据包
    int flag = 1;//判断循环的标志位
    pcap_if_t* count2; //遍历用的指针2
    for (count2 = devices; count2 != NULL; count2 = count2->next) {
        cout << "当前网络设备接口卡名字为：" << count2->name << endl;
        //打开网络接口
        //指定获取数据包最大长度为65536,可以确保程序可以抓到整个数据包
        //指定时间范围为200ms
        pcap_t* point = pcap_open(count2->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 200, NULL, errbuf);
        if (point == NULL) {
            cout << "打开当前网络接口失败" << endl;  //打开当前网络接口失败，继续下一个接口
            continue;
        }
        flag = 1;
        while (flag) {      //在打开的网络接口卡上捕获其所有的网络数据包
            struct pcap_pkthdr* pkt_header;//保存了捕获数据包的基本信息，比如捕获的时间戳、数据包的长度等
            const u_char* packetData;  //指向捕获到的数据包

            int result = pcap_next_ex(point, &pkt_header, &packetData); //得到pcap_next_ex的返回结果
            if (result == 0) {  //未捕获到数据包
                cout << "在指定时间范围（read_timeout)内未捕获到数据包" << endl;
                flag = 0;
                continue;
            }
            else if (result == -1) {  //调用过程发生错误
                cout << "捕获数据包出错" << endl;
                break;
            }
            else {  //result=1，捕获成功

                // 解析数据包
                         // 提取源MAC地址（前6字节）
                cout << "源MAC地址: ";
                for (int i = 0; i < 6; ++i) {
                    printf("%02X", packetData[i]);
                    if (i < 5) cout << ":";
                }
                cout << endl;

                // 提取目的MAC地址（接下来的6字节）
                cout << "目的MAC地址: ";
                for (int i = 6; i < 12; ++i) {
                    printf("%02X", packetData[i]);
                    if (i < 11) cout << ":";
                }
                cout << endl;
                // 提取类型/长度字段的值（接下来的2字节）
                uint16_t type = (packetData[12] << 8) + packetData[13];
                cout << "类型/长度: " << hex << type << dec << endl;

                //提取源IP地址（IPv4头部中的26到30字节）
                cout << "源IP地址: ";
                for (int i = 26; i < 30; ++i) {
                    printf("%d", packetData[i]);
                    if (i < 29) cout << ".";
                }
                cout << std::endl;
                // 提取目的IP地址（IPv4头部中的30到34字节）
                std::cout << "目的IP地址: ";
                for (int i = 30; i < 34; ++i) {
                    printf("%d", packetData[i]);
                    if (i < 33) cout << ".";
                }
                cout << endl;
                cout << "----------------------------------------------" << endl;

            }
        }
        // 关闭设备
        pcap_close(point);
    }
    pcap_freealldevs(devices); //释放网络接口设备列表
    return 0;
}
