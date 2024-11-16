#include <iostream>
#include <pcap.h>
#include <thread>
#include <mutex>
#include <queue>
#include <cstring>
#include <netinet/ip.h> 
#include <netinet/tcp.h> 
#include <arpa/inet.h> 
#include <string>
#include <chrono>
#include <ctime>
#include <condition_variable>
using namespace std;

#define HANDLER_1_IP_START "11.0.0.3"
#define HANDLER_1_IP_END "11.0.0.200"
#define HANDLER_2_IP_START "12.0.0.3"
#define HANDLER_2_IP_END "12.0.0.200"
#define HANDLER_2_PORT 8080


pcap_t* ptr_d;

int OFFSET = 0;

mutex mtx;


struct packet_data {
    const u_char* data;
    pcap_pkthdr* header;
    int number;
    uint16_t dst_port;
    uint16_t src_port;
    short protocol; 
};


class Packet_handler {
    public:

        short number;

        queue<struct packet_data> packet_line;

        bool END_FLAG;

        mutex hq_mutex; 
        
        mutex m;

        condition_variable cv;
        
        bool ready;
        
        Packet_handler(short h_num) {
            number = h_num;
            END_FLAG = false;
            ready = false;
        }

        void handle() {
                       
            pcap_dumper_t* dumper = pcap_dump_open(ptr_d, ("result_" + to_string(number) + ".pcap").c_str());
            
            while (true) {
                hq_mutex.lock();
                if ((packet_line.empty()) && END_FLAG){
                    hq_mutex.unlock();
                    break;
                }
                else if (packet_line.empty() && !END_FLAG){
                    hq_mutex.unlock();
                    std::unique_lock<std::mutex> lk(m);
                    cv.wait(lk, [this]{return ready;});
                    continue;   

                }
                hq_mutex.unlock();

                int packet_save_flag = 1;
                
                hq_mutex.lock();
                
                struct packet_data current_packet = packet_line.front();

                packet_line.pop();

                if (packet_line.empty()) {
                    ready = false;
                }
                
                hq_mutex.unlock();

                if (current_packet.header == NULL || current_packet.data == NULL){
                    mtx.lock();
                    cout << "PACKET ERROR" << endl;
                    mtx.unlock();
                }
                else{

                    if (number == 1 && current_packet.dst_port == 7070) {
                        mtx.lock();
                        cout << "Обработчик 1: Пакет под номером " << current_packet.number << " игнорируется" << endl;
                        mtx.unlock();
                        packet_save_flag = 0;

                    }
                    else if (number == 2){
                            for (int i = 0; i < current_packet.header->caplen; i++) {
                                if (current_packet.data[i] == 'x'){                                    
                                    current_packet.header->caplen = i+1;
                                    break;
                                }
                            }
                            packet_save_flag = 1;
                    }
                    else if (number == 3){

                        if (current_packet.protocol == IPPROTO_TCP) {

                            this_thread::sleep_for(chrono::milliseconds(2000));
                            time_t currentTime = time(nullptr);
                            
                            if (currentTime % 2 == 0) {
                                packet_save_flag = 1;
                            }
                            else {
                                packet_save_flag = 0;
                            }

                        }
                        else if (current_packet.protocol == IPPROTO_UDP) {

                            if(current_packet.dst_port == current_packet.src_port) {

                                packet_save_flag = 1;

                                mtx.lock();
                                cout << "Обработчик 2: Найдено совпадение port = " << current_packet.dst_port << endl;
                                mtx.unlock();

                            }
                            else {
                                packet_save_flag = 0;
                            }

                        }
                    }
                    
                    if (packet_save_flag) {
                        pcap_dump((u_char*)dumper, current_packet.header, current_packet.data);
                    }
                    free((void*) current_packet.data);
                    free((void*) current_packet.header);
                }

            }
                        
            pcap_dump_close(dumper);
            
        }

};


uint32_t ip_to_int(const std::string& ip_str) {
    struct in_addr addr;
    inet_pton(AF_INET, ip_str.c_str(), &addr);
    return ntohl(addr.s_addr);
}


void offset_setting(){

    int type = pcap_datalink(ptr_d);

    switch (type) {
        case DLT_EN10MB:
            OFFSET = 14;
            break;
        case DLT_RAW: 
            OFFSET = 0;
            break;
        case DLT_IPV4: 
            OFFSET = 0;
            break;
        case DLT_IPV6: 
            OFFSET = 0;
            break;
        case DLT_PPP_SERIAL:
            OFFSET = 4;
            break;
        case DLT_PPP_ETHER:
            OFFSET = 8;
            break;
        case DLT_IEEE802_11_RADIO:
            OFFSET = 18;
            break;
        case DLT_IEEE802_11:
            OFFSET = 24;
            break;
        case DLT_LINUX_SLL: 
            OFFSET = 16;
            break;
        case DLT_NULL:
            OFFSET = 4;
            break;
        case DLT_LOOP:
            OFFSET = 4;
            break;
        case DLT_PPP:
            OFFSET = 4;
            break;
        case DLT_FDDI:
            OFFSET = 13;
            break;
        default:
            fprintf(stderr, "Unsupported datalink type: %d\n", type);
            pcap_close(ptr_d);
            exit(1);
  }

}


void manager (char* filename, Packet_handler &hd1, Packet_handler &hd2, Packet_handler &hd3) {

    struct pcap_pkthdr* header;
    const u_char* packet;

    offset_setting();

    uint32_t handler1_ip_start = ip_to_int(HANDLER_1_IP_START);
    uint32_t handler1_ip_end = ip_to_int(HANDLER_1_IP_END);
    uint32_t handler2_ip_start = ip_to_int(HANDLER_2_IP_START);
    uint32_t handler2_ip_end = ip_to_int(HANDLER_2_IP_END);

    int counter = 1;
    
    while (pcap_next_ex(ptr_d, &header, &packet) >= 0) {
            
        const struct ip* ip_header = (struct ip*)(packet + OFFSET); 
        uint32_t dst_ip = ntohl(ip_header->ip_dst.s_addr);
        uint16_t dst_port = 0;
            
        if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {

            const struct tcphdr* tcp_udp_header = (struct tcphdr*)(packet + OFFSET + (ip_header->ip_hl * 4));
            dst_port = ntohs(tcp_udp_header->th_dport);
            
            struct packet_data cur_data;

            struct pcap_pkthdr* save_header = (struct pcap_pkthdr*) malloc(sizeof(struct pcap_pkthdr));
            *save_header = *header;

            u_char* save_packet = (u_char*) malloc(header->caplen);
            memcpy(save_packet, packet, header->caplen); 

            cur_data.data = save_packet;
            cur_data.header = save_header;
            cur_data.number = counter;
            cur_data.dst_port = dst_port;
            cur_data.src_port = tcp_udp_header->th_sport;
            cur_data.protocol = ip_header->ip_p;
            
            counter++;

            if (dst_ip >= handler1_ip_start && dst_ip <= handler1_ip_end) {
                hd1.hq_mutex.lock();
                hd1.packet_line.push(cur_data);
                hd1.hq_mutex.unlock();
                std::lock_guard<std::mutex> lk(hd1.m);
                hd1.ready = true;
                hd1.cv.notify_one();
            }
            else if (dst_ip >= handler2_ip_start && dst_ip <= handler2_ip_end && dst_port == HANDLER_2_PORT) {
                hd2.hq_mutex.lock();
                hd2.packet_line.push(cur_data);
                hd2.hq_mutex.unlock();
                std::lock_guard<std::mutex> lk(hd2.m);
                hd2.ready = true;
                hd2.cv.notify_one();
            } 
            else {
                hd3.hq_mutex.lock();
                hd3.packet_line.push(cur_data);
                hd3.hq_mutex.unlock();
                std::lock_guard<std::mutex> lk(hd3.m);
                hd3.ready = true;
                hd3.cv.notify_one();
            }
        }

    }
    hd1.END_FLAG = true;
    hd2.END_FLAG = true;
    hd3.END_FLAG = true;

    std::lock_guard<std::mutex> lk(hd1.m);
    hd1.ready = true;
    hd1.cv.notify_one();
    std::lock_guard<std::mutex> lk2(hd2.m);
    hd2.ready = true;
    hd2.cv.notify_one();
    std::lock_guard<std::mutex> lk3(hd3.m);
    hd3.ready = true;
    hd3.cv.notify_one();
}


int main(int argc, char* argv[]) {

    if (argv[1] == NULL) {
        cout << "Error : first argument must be the path to the \"*.pcap\" file" << endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(argv[1], errbuf);

    if (pcap == NULL) {
        cerr << "Error opening file: " << errbuf << std::endl;
        return 1;
    }

    ptr_d = pcap;

    Packet_handler h1 {1};
    Packet_handler h2 {2};
    Packet_handler h3 {3};
    
    thread handler1([&h1]() { h1.handle(); });
    thread handler2([&h2]() { h2.handle(); });
    thread handler3([&h3]() { h3.handle(); });
    thread mng (manager, argv[1], std::ref(h1), std::ref(h2), std::ref(h3));

    handler1.join();
    handler2.join();
    handler3.join();
    mng.join();

    pcap_close(pcap);

    return 0;
}   
