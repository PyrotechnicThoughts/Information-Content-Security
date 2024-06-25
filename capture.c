#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <stdint.h>

#include "hash_table.h"
#include "decrypt.h"

#define SNAP_LEN 65536 // 用于指定捕获数据包时的最大长度

// 定义 TLS 记录层消息类型
#define TLS_HANDSHAKE 0x16
#define TLS_APPLICATION_DATA 0x17
#define TLS_ALERT 0x15
#define TLS_CHANGE_CIPHER_SPEC 0x14
#define TLS_HEARTBEAT 0x18

// 定义 TLS 握手消息类型
#define TLS_CLIENT_HELLO 0x01
#define TLS_SERVER_HELLO 0x02
#define TLS_CERTIFICATE 0x0B
#define TLS_SERVER_KEY_EXCHANGE 0x0C
#define TLS_CLIENT_KEY_EXCHANGE 0x0D
#define TLS_CERTIFICATE_REQUEST 0x0E
#define TLS_SERVER_HELLO_DONE 0x0F
#define TLS_CERTIFICATE_VERIFY 0x10
#define TLS_CLIENT_HELLO_DONE 0x14
#define TLS_ENCRYPTED_HANDSHAKE_MESSAGE 0x16

typedef unsigned char u_char;

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);

char *timestamp_to_human_readable(const struct timeval *timestamp);

void handle_ethernet(const u_char *pkt_data);
void handle_ipv4(const struct pcap_pkthdr *header, const unsigned char *pkt_data);
void handle_ipv6(const u_char *pkt_data);
void handle_tcp(const struct pcap_pkthdr *header, const u_char *pkt_data, unsigned int ip_header_len);
void handle_tls(const struct pcap_pkthdr *header, const u_char *pkt_data, unsigned int tcp_data_len, uint16_t src_port, uint16_t dest_port);

const char *FRAME_STR = "- Frame";
const char *CAPLEN_STR = "cap";
const char *LEN_STR = "len";
const char *ETHERNET_STR = "- Ethernet";
const char *IPV4_STR = "- IPV4";
const char *IPV6_STR = "- IPV6";
const char *TCP_STR = "- TCP";
const char *TLS_STR = "- TLS";
const char *HANDSHAKE_STR = "Handshake Protocol";

long long frame_seq = 0;

// 定义一个函数来将Cipher Suite代码转换为名称
const char *get_cipher_suite_name(uint16_t cipher_suite)
{
    switch (cipher_suite)
    {
    case 0x0000:
        return "TLS_NULL_WITH_NULL_NULL";
    case 0x0001:
        return "TLS_RSA_WITH_NULL_MD5";
    case 0x0002:
        return "TLS_RSA_WITH_NULL_SHA";
    case 0x0004:
        return "TLS_RSA_WITH_RC4_128_MD5";
    case 0x0005:
        return "TLS_RSA_WITH_RC4_128_SHA";
    case 0x002F:
        return "TLS_RSA_WITH_AES_128_CBC_SHA";
    case 0x0035:
        return "TLS_RSA_WITH_AES_256_CBC_SHA";
    case 0x009C:
        return "TLS_RSA_WITH_AES_128_GCM_SHA256";
    case 0x009D:
        return "TLS_RSA_WITH_AES_256_GCM_SHA384";
    case 0x1301:
        return "TLS_AES_128_GCM_SHA256";
    case 0x1302:
        return "TLS_AES_256_GCM_SHA384";
    case 0x1303:
        return "TLS_CHACHA20_POLY1305_SHA256";
    case 0xC02F:
        return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    // 添加更多的Cipher Suite代码和名称
    default:
        return "Unknown Cipher Suite";
    }
}

const char *get_tls_version_string(uint16_t tls_version)
{
    switch (tls_version)
    {
    case 0x0301:
        return "TLS 1.0";
    case 0x0302:
        return "TLS 1.1";
    case 0x0303:
        return "TLS 1.2";
    case 0x0304:
        return "TLS 1.3";
    default:
        return "Unknown";
    }
}

#define FRAME_HEADER_LENGTH 9

typedef struct
{
    uint32_t length;
    uint8_t type;
    uint8_t flags;
    uint8_t reserved;
    uint32_t stream_id;
    uint8_t *payload;
} http2_frame;

void parse_frame_header(const uint8_t *data, http2_frame *frame)
{
    frame->length = (data[0] << 16) | (data[1] << 8) | data[2];
    frame->type = data[3];
    frame->flags = data[4];
    frame->reserved = (data[5] & 0x80) >> 7;
    frame->stream_id = ((data[5] & 0x7F) << 24) | (data[6] << 16) | (data[7] << 8) | data[8];
}

void print_frame_info(const http2_frame *frame)
{
    printf("---- [Frame Length]: %u\n", frame->length);
    printf("---- [Frame Type]: %u\n", frame->type);
    printf("---- [Frame Flags]: %u\n", frame->flags);
    printf("---- [Stream ID]: %u\n", frame->stream_id);
}

void handle_data_frame(const http2_frame *frame)
{
    const uint8_t *payload = frame->payload;
    uint32_t length = frame->length;
    uint8_t flags = frame->flags;

    uint8_t pad_length = 0;
    if (flags & 0x08)
    { // PADDED flag
        pad_length = payload[0];
        payload += 1; // Move payload pointer forward
        length -= 1;
    }

    uint32_t data_length = length - pad_length;
    printf("---- DATA Frame, data length: %u\n", data_length);

    printf("---- Data: ");
    for (uint32_t i = 0; i < data_length; ++i)
    {
        printf("%02x", payload[i]);
    }
    printf("\n");
    printf("%s\n", payload);

    if (flags & 0x01)
    { // END_STREAM flag
        printf("---- END_STREAM flag is set\n");
    }

    if (pad_length > 0)
    {
        printf("---- Padding: ");
        for (uint32_t i = data_length; i < data_length + pad_length; ++i)
        {
            printf("%02x", payload[i]);
        }
        printf("\n");
    }
}

void handle_frame_payload(const http2_frame *frame)
{
    // 根据帧的类型解析有效载荷
    switch (frame->type)
    {
    case 0x00: // DATA
        printf("-- DATA Frame\n");
        print_frame_info(frame);
        handle_data_frame(frame);
        break;
    case 0x01: // HEADERS
        printf("-- HEADERS Frame\n");
        print_frame_info(frame);
        // 处理HEADERS帧的payload
        break;
    // 添加其他帧类型的处理
    default:
        printf("-- Unknown Frame Type: %u\n", frame->type);
    }
}

void parse_http2_data(const uint8_t *data, size_t length)
{
    size_t offset = 0;

    while (offset < length)
    {
        if (length - offset < FRAME_HEADER_LENGTH)
        {
            printf("---- Maybe not HTTP2 or this is an isncomplete frame header\n");
            return;
        }

        http2_frame frame;
        parse_frame_header(data + offset, &frame);

        if (length - offset < FRAME_HEADER_LENGTH + frame.length)
        {
            printf("---- Maybe not HTTP2 or this is an incomplete frame payload\n");
            return;
        }

        frame.payload = malloc(frame.length);
        if (frame.payload == NULL)
        {
            printf("[ERROR] Memory allocation failed\n");
            return;
        }

        memcpy(frame.payload, data + offset + FRAME_HEADER_LENGTH, frame.length);
        handle_frame_payload(&frame);

        free(frame.payload);

        offset += FRAME_HEADER_LENGTH + frame.length;
    }
}

HashTable *table;
tls_session_info sessions[65535 + 1];
tls_record_info record;

int main(int argc, char **argv)
{
    table = get_dict_from_sslkeylog();
    // session.ability = 0;

    char *dev = NULL; /* capture device name */       /* 捕获设备名称 */
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */ /* 错误信息缓冲区 */
    pcap_t *handle; /* packet capture handle */       /* 数据包捕获句柄 */
    pcap_if_t *alldev, *p;

    // char filter_exp[] = "tcp and (host baidu.com or host www.baidu.com)"; /* filter expression [3] */ /* 过滤器表达式 */
    char filter_exp[] = "tcp and (host mail.qq.com or host wx.mail.qq.com or host ssl.ptlogin2.qq.com)";
    // char filter_exp[] = "tcp and (host mail.hit.edu.cn)";
    // char filter_exp[] = "tcp and (host outlook.live.com)";
    // char filter_exp[] = "tcp and (host mail.163.com)";
    // char filter_exp[] = "tcp port 443";

    struct bpf_program fp; /* compiled filter program (expression) */ /* 编译后的过滤器程序 */
    // bpf_u_int32 mask; /* subnet mask */                               /* 子网掩码 */
    // bpf_u_int32 net; /* ip */                                         /* IP地址 */
    int num_packets = 10000; /* number of packets to capture */ /* 要捕获的数据包数量 */

    /* 检查命令行参数中是否指定了捕获设备名称 */
    /* check for capture device name on command-line */
    if (argc == 2)
    {
        dev = argv[1];
    }
    else if (argc > 2)
    {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        /* 如果没有在命令行指定捕获设备，则查找可用的捕获设备 */
        /* find a capture device if not specified on command-line */
        int i = 0, num;
        if (pcap_findalldevs(&alldev, errbuf) == -1)
        {
            printf("find all devices is error\n");
            return 0;
        }
        for (p = alldev; p; p = p->next)
        {
            printf("%d:%s\n", ++i, p->name);
            if (p->description)
            {
                printf("%s\n", p->description);
            }
        }
        printf("please input which interface you want to use\n");
        scanf("%d", &num);
        if (num < 1 || num > i)
        {
            printf("interface is unavillible\n");
            return 0;
        }
        for (p = alldev, i = 1; i <= num; p = p->next, i++)
            dev = p->name;
        if (dev == NULL)
        {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* 打印捕获配置信息 */
    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    /* 打开捕获设备 */
    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* 确保我们在以太网设备上进行捕获 */
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* 编译过滤器表达式 */
    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, 24) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* 应用编译后的过滤器 */
    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* 现在可以设置回调函数 */
    /* now we can set our callback function */
    pcap_loop(handle, num_packets, dispatcher_handler, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("\nCapture complete.\n");

    free(table);

    return 0;
}

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    char *time_str = timestamp_to_human_readable(&(header->ts));
    printf("[ %s ]", time_str);
    printf("\n");

    printf("%-5s #%-8lld\n", FRAME_STR, ++frame_seq);

    printf("---- %3s:%6d bytes\n", CAPLEN_STR, header->caplen);
    printf("---- %3s:%6d bytes\n", LEN_STR, header->len);

    handle_ethernet(pkt_data);

    struct ethhdr *eth_header = (struct ethhdr *)pkt_data;
    if (ntohs(eth_header->h_proto) == ETH_P_IP)
    {
        handle_ipv4(header, pkt_data);
    }
    else if (ntohs(eth_header->h_proto) == ETH_P_IPV6)
    {
        handle_ipv6(pkt_data);
    }
    else
    {
        printf("Not an IP packet\n");
    }

    printf("\n");
}

// 将时间戳转换为人类可读的时间格式，并返回字符串
char *timestamp_to_human_readable(const struct timeval *timestamp)
{
    time_t rawtime = timestamp->tv_sec;
    struct tm *timeinfo;
    char *buffer = (char *)malloc(80 * sizeof(char));

    if (buffer == NULL)
    {
        fprintf(stderr, "内存分配失败\n");
        exit(EXIT_FAILURE);
    }

    timeinfo = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
    sprintf(buffer + strlen(buffer), ".%06ld", timestamp->tv_usec);
    return buffer;
}

void handle_ethernet(const u_char *pkt_data)
{

    // 解析以太网帧
    // Ethernet header length: 14 bytes
    // Source MAC address: pkt_data[6] - pkt_data[11]
    // Destination MAC address: pkt_data[0] - pkt_data[5]

    unsigned char *src_mac = (unsigned char *)(pkt_data + 6);
    unsigned char *dst_mac = (unsigned char *)pkt_data;

    printf("%-15s", ETHERNET_STR);
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf(" ---> ");
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    printf("\n");
}

void handle_ipv4(const struct pcap_pkthdr *header, const unsigned char *pkt_data)
{
    struct iphdr *ip_header = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));

    printf("%-15s", IPV4_STR);
    printf("%17s", inet_ntoa(*(struct in_addr *)&(ip_header->saddr)));
    printf(" ---> ");
    printf("%17s", inet_ntoa(*(struct in_addr *)&(ip_header->daddr)));
    printf("\n");

    // 解析IP头部长度 (ihl字段，单位是4字节)
    unsigned int ip_header_len = ip_header->ihl * 4;
    printf("---- IP Header Length: %u bytes\n", ip_header_len);

    // 解析IP数据部分长度 (总长度减去IP头部长度)
    unsigned int ip_total_len = ntohs(ip_header->tot_len);
    unsigned int ip_data_len = ip_total_len - ip_header_len;
    printf("---- IP Data Length: %u bytes\n", ip_data_len);

    if (ip_header->protocol == IPPROTO_TCP)
    {
        handle_tcp(header, pkt_data, ip_header_len);
    }
}

void handle_ipv6(const unsigned char *pkt_data)
{
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)(pkt_data + sizeof(struct ethhdr));
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

    printf("%-15s", IPV6_STR);
    printf("%s", src_ip);
    printf(" ---> ");
    printf("%s", dst_ip);
    printf("\n");
}

void handle_tcp(const struct pcap_pkthdr *header, const u_char *pkt_data, unsigned int ip_header_len)
{
    // struct tcphdr *tcp_header = (struct tcphdr *)(pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    struct tcphdr *tcp_header = (struct tcphdr *)(pkt_data + sizeof(struct ethhdr) + ip_header_len);

    uint16_t dest_port = ntohs(tcp_header->dest);
    uint16_t src_port = ntohs(tcp_header->source);
    printf("%-15s", TCP_STR);
    printf("%17d ---> %17d", src_port, dest_port);
    printf("\n");
    printf("---- Seq: %u ", ntohl(tcp_header->seq));
    printf("Ack: %u ", ntohl(tcp_header->ack_seq));
    printf("Data Offset: %d", tcp_header->doff);
    printf("\n");

    // 解析TCP头部长度 (doff字段，单位是4字节)
    unsigned int tcp_header_len = tcp_header->doff * 4;
    printf("---- TCP Header Length: %u bytes\n", tcp_header_len);

    // 计算传输层数据部分长度
    unsigned int tcp_data_len = ntohs(((struct iphdr *)(pkt_data + sizeof(struct ethhdr)))->tot_len) - ip_header_len - tcp_header_len;
    printf("---- TCP Data Length: %u bytes\n", tcp_data_len);

    // 这几种只在建立TCP或释放TCP连接中
    int check_tls = 1;
    if (tcp_header->fin || tcp_header->syn || tcp_header->rst || tcp_data_len == 0)
    {
        check_tls = 0;
    }

    printf("---- FIN: %d ", (tcp_header->fin) ? 1 : 0);
    printf("SYN: %d ", (tcp_header->syn) ? 1 : 0);
    printf("RST: %d ", (tcp_header->rst) ? 1 : 0);
    printf("PSH: %d ", (tcp_header->psh) ? 1 : 0);
    printf("ACK: %d ", (tcp_header->ack) ? 1 : 0);
    printf("URG: %d ", (tcp_header->urg) ? 1 : 0);
    printf("\n");

    printf("---- Win: %d ", ntohs(tcp_header->window));
    printf("Checksum: 0x%x ", ntohs(tcp_header->check));
    printf("Urgent Pointer: %d", ntohs(tcp_header->urg_ptr));
    printf("\n");

    if (check_tls && (ntohs(tcp_header->source) == 443 || ntohs(tcp_header->dest) == 443))
    {
        handle_tls(header, pkt_data, tcp_data_len, src_port, dest_port);
    }
}

void parse_tls_client_hello(const u_char *tls_handshake, uint16_t src_port, uint16_t dest_port)
{
    // 解析Client Hello的长度
    uint16_t length = (tls_handshake[1] << 16) | (tls_handshake[2] << 8) | tls_handshake[3];
    printf("---- Length: %d\n", length);

    // 解析TLS版本号
    uint16_t tls_version = (tls_handshake[4] << 8) | tls_handshake[5];
    printf("-- Version: %s\n", get_tls_version_string(tls_version));

    // 解析随机数
    printf("---- Random: ");
    for (int i = 0; i < 32; ++i)
    {
        printf("%02X", tls_handshake[6 + i]);
    }
    printf("\n");

    int client_port = (src_port == 443) ? (dest_port) : (src_port);

    memcpy(sessions[client_port].client_random, tls_handshake + 6, CLIENT_RANDOM_LENGTH);
    sessions[client_port].has_client_random = 1;

    unsigned char hex_data[CLIENT_RANDOM_LENGTH];
    memcpy(hex_data, tls_handshake + 6, CLIENT_RANDOM_LENGTH);
    char str_data[CLIENT_RANDOM_LENGTH * 2];
    for (int i = 0; i < CLIENT_RANDOM_LENGTH; ++i)
    {
        sprintf((char *)&str_data[i * 2], "%02x", hex_data[i]);
    }

    printf("---- Pre Master Key: ");
    char *pre_master_key = search_entry(table, str_data);
    if (pre_master_key != NULL)
    {
        printf("%s\n", pre_master_key);

        unsigned char hex_data[PRE_MASTER_SECRET_LENGTH];
        for (int i = 0; i < 2 * PRE_MASTER_SECRET_LENGTH; i += 2)
        {
            sscanf(&pre_master_key[i], "%2hhx", &hex_data[i / 2]);
        }

        memcpy(sessions[client_port].pre_master_secret, hex_data, PRE_MASTER_SECRET_LENGTH);

        sessions[client_port].has_pre_master_key = 1;
        sessions[client_port].has_server_random = 0;
    }
    else
    {
        printf("Not found. Reloading sslkeylogfile...\n");
        free_table(table);
        printf("---- Pre Master Key: ");
        table = get_dict_from_sslkeylog();
        pre_master_key = search_entry(table, str_data);

        if (pre_master_key == NULL)
        {
            printf("Not found.\n");
            sessions[client_port].has_pre_master_key = 0;
            sessions[client_port].has_server_random = 0;
        }
        else
        {
            printf("%s\n", pre_master_key);

            unsigned char hex_data[PRE_MASTER_SECRET_LENGTH];
            for (int i = 0; i < 2 * PRE_MASTER_SECRET_LENGTH; i += 2)
            {
                sscanf(&pre_master_key[i], "%2hhx", &hex_data[i / 2]);
            }

            memcpy(sessions[client_port].pre_master_secret, hex_data, PRE_MASTER_SECRET_LENGTH);

            sessions[client_port].has_pre_master_key = 1;
            sessions[client_port].has_server_random = 0;
        }
    }

    // 解析Session ID长度
    uint8_t session_id_length = tls_handshake[38];
    printf("---- Session ID Length: %d\n", session_id_length);

    // 解析Session ID
    printf("---- Session ID: ");
    for (int i = 0; i < session_id_length; ++i)
    {
        printf("%02X", tls_handshake[39 + i]);
    }
    printf("\n");
}

void parse_tls_server_hello(const u_char *tls_handshake, uint16_t src_port, uint16_t dest_port)
{
    // 解析Server Hello的长度
    uint16_t length = (tls_handshake[1] << 16) | (tls_handshake[2] << 8) | tls_handshake[3];
    printf("---- Length: %d\n", length);

    // 解析TLS版本号
    uint16_t tls_version = (tls_handshake[4] << 8) | tls_handshake[5];
    printf("-- Version: %s\n", get_tls_version_string(tls_version));

    // 解析随机数
    printf("---- Random: ");
    for (int i = 0; i < 32; ++i)
    {
        printf("%02X", tls_handshake[6 + i]);
    }
    printf("\n");

    int client_port = (src_port == 443) ? (dest_port) : (src_port);

    memcpy(sessions[client_port].server_random, tls_handshake + 6, SERVER_RANDOM_LENGTH);
    int res = generate(&sessions[client_port], &record);
    if (res == 1)
    {
        sessions[client_port].has_server_random = 1;
    }

    if (sessions[client_port].has_client_random && sessions[client_port].has_server_random && sessions[client_port].has_pre_master_key)
    {
        printf("---- Ready for decryption.\n");
    }
    else if (sessions[client_port].has_client_random && sessions[client_port].has_server_random)
    {
        printf("---- Reloading pre master key from sslkeylogfile...\n");

        unsigned char hex_data[CLIENT_RANDOM_LENGTH];
        memcpy(hex_data, sessions[client_port].client_random, CLIENT_RANDOM_LENGTH);
        char str_data[CLIENT_RANDOM_LENGTH * 2];
        for (int i = 0; i < CLIENT_RANDOM_LENGTH; ++i)
        {
            sprintf((char *)&str_data[i * 2], "%02x", hex_data[i]);
        }

        char *pre_master_key = search_entry(table, str_data);
        if (pre_master_key != NULL)
        {
            printf("---- Get pre master key: %s\n", pre_master_key);

            unsigned char hex_data[PRE_MASTER_SECRET_LENGTH];
            for (int i = 0; i < 2 * PRE_MASTER_SECRET_LENGTH; i += 2)
            {
                sscanf(&pre_master_key[i], "%2hhx", &hex_data[i / 2]);
            }

            memcpy(sessions[client_port].pre_master_secret, hex_data, PRE_MASTER_SECRET_LENGTH);

            sessions[client_port].has_pre_master_key = 1;
        }
        else
        {
            printf("---- Not found.\n");
        }
    }
    else
    {
        printf("---- session on port [ %d ] can't be decrypted.\n", client_port);
    }

    // 解析Session ID长度
    uint8_t session_id_length = tls_handshake[38];
    printf("---- Session ID Length: %d\n", session_id_length);

    // 解析Session ID
    printf("---- Session ID: ");
    for (int i = 0; i < session_id_length; ++i)
    {
        printf("%02X", tls_handshake[39 + i]);
    }
    printf("\n");

    // 解析Cipher Suite
    int cipher_suite_offset = 39 + session_id_length;
    uint16_t cipher_suite = (tls_handshake[cipher_suite_offset] << 8) | tls_handshake[cipher_suite_offset + 1];
    printf("---- Cipher Suite: 0x%04X (%s)\n", cipher_suite, get_cipher_suite_name(cipher_suite));

    // 解析压缩方法
    int compression_method_offset = cipher_suite_offset + 2;
    uint8_t compression_method = tls_handshake[compression_method_offset];
    printf("---- Compression Method: %d\n", compression_method);
}

void handle_tls(const struct pcap_pkthdr *header, const u_char *pkt_data, unsigned int tcp_data_len, uint16_t src_port, uint16_t dest_port)
{

    printf("%-15s", TLS_STR);
    printf("Total Length: %d", tcp_data_len);
    printf("\n");

    unsigned int add_up = 0;

    int client_port = (src_port == 443) ? (dest_port) : (src_port);

    if (header->caplen > sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + 5)
    {
        while (add_up < tcp_data_len)
        {
            const u_char *tls_record = pkt_data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + add_up;

            uint16_t tls_version = 0;
            uint16_t length = 0;
            // 解析TLS中 Content Type
            // 握手协议、加密数据等
            printf("-- [ Content Type ] ");
            switch (tls_record[0])
            {

            // 22
            case TLS_HANDSHAKE:
                printf("%s\n", HANDSHAKE_STR);

                // 解析Version
                tls_version = (tls_record[1] << 8) | tls_record[2];
                printf("-- Version: %s\n", get_tls_version_string(tls_version));

                // 解析Length
                length = (tls_record[3] << 8) | tls_record[4];
                printf("-- Length: %d\n", length);
                add_up += length + 5;

                const u_char *tls_handshake = tls_record + 5;
                switch (tls_handshake[0])
                {
                // 1
                case TLS_CLIENT_HELLO:
                    printf("-- ClientHello\n");
                    printf("---- Handshake Type: Client Hello\n");
                    parse_tls_client_hello(tls_handshake, src_port, dest_port);
                    break;
                // 2
                case TLS_SERVER_HELLO:
                    printf("-- ServerHello\n");
                    printf("---- Handshake Type: Server Hello\n");
                    parse_tls_server_hello(tls_handshake, src_port, dest_port);
                    break;
                case TLS_CERTIFICATE:
                    printf("-- Certificate\n");
                    // 解析证书
                    // parse_tls_certificate(tls_handshake);
                    break;
                case TLS_SERVER_KEY_EXCHANGE:
                    printf("-- ServerKeyExchange\n");
                    // 解析服务器密钥交换信息
                    // parse_tls_server_key_exchange(tls_handshake);
                    break;
                // 客户端密钥交换
                case TLS_CLIENT_KEY_EXCHANGE:
                    printf("-- ClientKeyExchange\n");
                    // 解析客户端密钥交换信息
                    // parse_tls_client_key_exchange(tls_handshake);
                    break;
                // 证书请求
                case TLS_CERTIFICATE_REQUEST:
                    printf("-- CertificateRequest\n");
                    // 解析证书请求信息
                    // parse_tls_certificate_request(tls_handshake);
                    break;
                // 服务器Hello完成
                case TLS_SERVER_HELLO_DONE:
                    printf("-- ServerHelloDone\n");
                    // 无需额外解析信息
                    break;
                // 证书验证
                case TLS_CERTIFICATE_VERIFY:
                    printf("-- CertificateVerify\n");
                    // 解析证书验证信息
                    // parse_tls_certificate_verify(tls_handshake);
                    break;
                // 客户端Hello完成
                case TLS_CLIENT_HELLO_DONE:
                    printf("-- ClientHelloDone\n");
                    // 无需额外解析信息
                    break;
                // 被加密的握手消息
                case TLS_ENCRYPTED_HANDSHAKE_MESSAGE:
                    printf("-- EncryptedHandshakeMessage\n");
                    // 无法解析被加密的消息内容，只打印类型即可
                    break;
                default:
                    printf("-- Other handshake message (type %d)", tls_handshake[0]);
                    break;
                }
                break;

            // 23
            case TLS_APPLICATION_DATA:
                printf("Application Data\n");

                // 解析Version
                tls_version = (tls_record[1] << 8) | tls_record[2];
                printf("-- Version: %s\n", get_tls_version_string(tls_version));

                // 打印加密的数据部分
                uint16_t app_data_length = (tls_record[3] << 8) | tls_record[4];
                printf("-- Length: %d\n", app_data_length);
                add_up += app_data_length + 5;

                printf("-- Encrypted Data: ");
                for (int i = 5; i < 5 + app_data_length; ++i)
                {
                    printf("%02X", tls_record[i]);
                }
                printf("\n");

                if (sessions[client_port].has_client_random && sessions[client_port].has_server_random && sessions[client_port].has_pre_master_key)
                {

                    record.ciphertext_length = app_data_length - SEQ_LENGTH - AUTH_TAG_LENGTH;
                    record.ciphertext = (u_char *)malloc(record.ciphertext_length * sizeof(u_char));
                    memcpy(record.ciphertext, tls_record + 5 + SEQ_LENGTH, record.ciphertext_length);

                    memcpy(record.seq, tls_record + 5, SEQ_LENGTH);

                    if (dest_port == 443)
                    {
                        // 客户端的数据
                        unsigned char temp_cache[CLIENT_IV_LENGTH + SEQ_LENGTH];
                        memcpy(temp_cache, sessions[client_port].client_iv, CLIENT_IV_LENGTH);
                        memcpy(temp_cache + CLIENT_IV_LENGTH, record.seq, SEQ_LENGTH);

                        memcpy(record.nonce, temp_cache, NONCE_LENGTH);

                        printf("-- client random: ");
                        for (int i = 0; i < CLIENT_RANDOM_LENGTH; ++i)
                        {
                            printf("%02x", sessions[client_port].client_random[i]);
                        }
                        printf("\n");

                        printf("-- server random: ");
                        for (int i = 0; i < SERVER_RANDOM_LENGTH; ++i)
                        {
                            printf("%02x", sessions[client_port].server_random[i]);
                        }
                        printf("\n");

                        printf("-- key expansion: ");
                        for (int i = 0; i < KEY_EXPANSION_LENGTH; ++i)
                        {
                            printf("%02x", sessions[client_port].key_expansion[i]);
                        }
                        printf("\n");

                        printf("-- client key: ");
                        for (int i = 0; i < CLIENT_KEY_LENGTH; ++i)
                        {
                            printf("%02x", sessions[client_port].client_key[i]);
                        }
                        printf("\n");

                        printf("-- client iv: ");
                        for (int i = 0; i < CLIENT_IV_LENGTH; ++i)
                        {
                            printf("%02x", sessions[client_port].client_iv[i]);
                        }
                        printf("\n");

                        printf("-- record.nonce: ");
                        for (int i = 0; i < NONCE_LENGTH; ++i)
                        {
                            printf("%02x", record.nonce[i]);
                        }
                        printf("\n");

                        printf("-- record.ciphertext: ");
                        for (int i = 0; i < record.ciphertext_length; ++i)
                        {
                            printf("%02x", record.ciphertext[i]);
                        }
                        printf("\n");

                        record.plaintext = (u_char *)malloc(record.ciphertext_length * sizeof(u_char));
                        record.plaintext_length = decrypt_aes_128_gcm(record.ciphertext, record.ciphertext_length, sessions[client_port].client_key, record.nonce, record.plaintext);

                        printf("-- Decrypted data: ");
                        if (record.plaintext_length < 0)
                        {
                            printf("Decrypted failed\n");
                        }

                        for (int i = 0; i < record.plaintext_length; ++i)
                        {
                            printf("%02x", record.plaintext[i]);
                        }
                        printf("\n");

                        printf("----------\n");
                        printf("%s\n", record.plaintext);
                        printf("----------\n");

                        parse_http2_data(record.plaintext, record.plaintext_length);

                        free(record.plaintext);
                    }
                    else
                    {
                        // 服务器的数据
                        unsigned char temp_cache[SERVER_IV_LENGTH + SEQ_LENGTH];
                        memcpy(temp_cache, sessions[client_port].server_iv, SERVER_IV_LENGTH);
                        memcpy(temp_cache + SERVER_IV_LENGTH, record.seq, SEQ_LENGTH);

                        memcpy(record.nonce, temp_cache, NONCE_LENGTH);

                        printf("-- client random: ");
                        for (int i = 0; i < CLIENT_RANDOM_LENGTH; ++i)
                        {
                            printf("%02x", sessions[client_port].client_random[i]);
                        }
                        printf("\n");

                        printf("-- server random: ");
                        for (int i = 0; i < SERVER_RANDOM_LENGTH; ++i)
                        {
                            printf("%02x", sessions[client_port].server_random[i]);
                        }
                        printf("\n");

                        printf("-- key expansion: ");
                        for (int i = 0; i < KEY_EXPANSION_LENGTH; ++i)
                        {
                            printf("%02x", sessions[client_port].key_expansion[i]);
                        }
                        printf("\n");

                        printf("-- server key: ");
                        for (int i = 0; i < CLIENT_KEY_LENGTH; ++i)
                        {
                            printf("%02x", sessions[client_port].server_key[i]);
                        }
                        printf("\n");

                        printf("-- server iv: ");
                        for (int i = 0; i < CLIENT_IV_LENGTH; ++i)
                        {
                            printf("%02x", sessions[client_port].server_iv[i]);
                        }
                        printf("\n");

                        printf("-- record.nonce: ");
                        for (int i = 0; i < NONCE_LENGTH; ++i)
                        {
                            printf("%02x", record.nonce[i]);
                        }
                        printf("\n");

                        printf("-- record.ciphertext: ");
                        for (int i = 0; i < record.ciphertext_length; ++i)
                        {
                            printf("%02x", record.ciphertext[i]);
                        }
                        printf("\n");

                        record.plaintext = (u_char *)malloc(record.ciphertext_length * sizeof(u_char));
                        record.plaintext_length = decrypt_aes_128_gcm(record.ciphertext, record.ciphertext_length, sessions[client_port].server_key, record.nonce, record.plaintext);

                        printf("-- Decrypted data: ");
                        if (record.plaintext_length < 0)
                        {
                            printf("Decrypted failed\n");
                        }

                        for (int i = 0; i < record.plaintext_length; ++i)
                        {
                            printf("%02x", record.plaintext[i]);
                        }
                        printf("\n");

                        printf("----------\n");
                        printf("%s\n", record.plaintext);
                        printf("----------\n");

                        parse_http2_data(record.plaintext, record.plaintext_length);

                        free(record.plaintext);
                    }

                    free(record.ciphertext);
                }
                else
                {
                    printf("-- Session now is not being ready for decrypting.\n");
                }

                break;
            // 21
            case TLS_ALERT:
                printf("Encrypted Alert\n");

                // 解析Version
                tls_version = (tls_record[1] << 8) | tls_record[2];
                printf("-- Version: %s\n", get_tls_version_string(tls_version));

                // 解析Length
                length = (tls_record[3] << 8) | tls_record[4];
                printf("-- Length: %d\n", length);
                add_up += length + 5;

                break;
            // 20
            case TLS_CHANGE_CIPHER_SPEC:
                printf("Change Cipher Spec\n");

                // 解析Version
                tls_version = (tls_record[1] << 8) | tls_record[2];
                printf("-- Version: %s\n", get_tls_version_string(tls_version));

                // 解析Length
                length = (tls_record[3] << 8) | tls_record[4];
                printf("-- Length: %d\n", length);
                add_up += length + 5;

                break;

            default:
                printf("Unknown Type (%d)\n", tls_record[0]);

                add_up = tcp_data_len;
            }
        } // end while
    } // end if
    else
    {
        printf("Maybe it is not a TLS packet, or it's an invalid TLS packet");
    }
    printf("\n");
}
