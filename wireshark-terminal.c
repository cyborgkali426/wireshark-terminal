###################################################################################################################################################################
#
# Author: Kali Goddess (Cyborg)
# Data: 10/02/2025
# Title: Wireshark Terminal
# Detail: wireshark-terminal is similar to Wireshark, but is only displayed in the terminal.
# Objective: The aim of wireshark-terminal is to be as portable as possible, as long as you run it with the root user.
#
###################################################################################################################################################################

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

// Variáveis globais para controle do número do pacote e tempo inicial
int packet_count = 0;
struct timeval start_time;

// Função para calcular o tempo relativo
double calculate_relative_time(const struct timeval *current_time) {
    return (current_time->tv_sec - start_time.tv_sec) +
           (current_time->tv_usec - start_time.tv_usec) / 1000000.0;
}

// Função para formatar endereços MAC
void format_mac_address(const u_char *mac, char *buffer, size_t buffer_size) {
    snprintf(buffer, buffer_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Função para processar pacotes ARP
void process_arp(const u_char *packet, char *info, size_t info_size) {
    struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));

    if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REQUEST) {
        snprintf(info, info_size, "Who has %d.%d.%d.%d? Tell %d.%d.%d.%d",
                 arp_hdr->arp_tpa[0], arp_hdr->arp_tpa[1], arp_hdr->arp_tpa[2], arp_hdr->arp_tpa[3],
                 arp_hdr->arp_spa[0], arp_hdr->arp_spa[1], arp_hdr->arp_spa[2], arp_hdr->arp_spa[3]);
    } else if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY) {
        snprintf(info, info_size, "%d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x",
                 arp_hdr->arp_spa[0], arp_hdr->arp_spa[1], arp_hdr->arp_spa[2], arp_hdr->arp_spa[3],
                 arp_hdr->arp_sha[0], arp_hdr->arp_sha[1], arp_hdr->arp_sha[2],
                 arp_hdr->arp_sha[3], arp_hdr->arp_sha[4], arp_hdr->arp_sha[5]);
    }
}

// Função para processar pacotes ICMPv6
void process_icmpv6(const u_char *packet, char *info, size_t info_size) {
    struct icmp6_hdr *icmpv6_hdr = (struct icmp6_hdr *)(packet + sizeof(struct ether_header) + 40);

    switch (icmpv6_hdr->icmp6_type) {
        case ND_NEIGHBOR_SOLICIT:
            snprintf(info, info_size, "Neighbor Solicitation for IPv6 address");
            break;
        case ND_NEIGHBOR_ADVERT:
            snprintf(info, info_size, "Neighbor Advertisement for IPv6 address");
            break;
        default:
            snprintf(info, info_size, "ICMPv6 Type %d", icmpv6_hdr->icmp6_type);
            break;
    }
}

// Função para processar pacotes capturados
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Incrementa o contador de pacotes
    packet_count++;

    // Calcula o tempo relativo
    double relative_time = calculate_relative_time(&pkthdr->ts);

    // Analisa o cabeçalho Ethernet
    struct ether_header *eth_hdr = (struct ether_header *)packet;

    char src_mac[18], dst_mac[18];
    format_mac_address(eth_hdr->ether_shost, src_mac, sizeof(src_mac));
    format_mac_address(eth_hdr->ether_dhost, dst_mac, sizeof(dst_mac));

    // Inicializa variáveis para Source, Destination, Protocol e Info
    char src_ip[INET6_ADDRSTRLEN] = "N/A";
    char dst_ip[INET6_ADDRSTRLEN] = "N/A";
    char protocol[10] = "Unknown";
    char info[100] = "N/A";

    // Verifica o tipo de pacote Ethernet
    switch (ntohs(eth_hdr->ether_type)) {
        case ETHERTYPE_IP: { // IPv4
            struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
            inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            // Determina o protocolo
            switch (ip_hdr->ip_p) {
                case IPPROTO_TCP: {
                    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_hdr->ip_hl << 2));
                    snprintf(protocol, sizeof(protocol), "TCP");
                    snprintf(info, sizeof(info), "Port %d -> %d", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
                    break;
                }
                case IPPROTO_UDP: {
                    struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_hdr->ip_hl << 2));
                    snprintf(protocol, sizeof(protocol), "UDP");
                    snprintf(info, sizeof(info), "Port %d -> %d", ntohs(udp_hdr->uh_sport), ntohs(udp_hdr->uh_dport));
                    break;
                }
                case IPPROTO_ICMP: {
                    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + (ip_hdr->ip_hl << 2));
                    snprintf(protocol, sizeof(protocol), "ICMP");
                    snprintf(info, sizeof(info), "Type %d", icmp_hdr->type);
                    break;
                }
                default: {
                    snprintf(protocol, sizeof(protocol), "IPv4");
                    break;
                }
            }
            break;
        }
        case ETHERTYPE_IPV6: { // IPv6
            struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

            // Determina o protocolo
            switch (ip6_hdr->ip6_nxt) {
                case IPPROTO_ICMPV6: {
                    snprintf(protocol, sizeof(protocol), "ICMPv6");
                    process_icmpv6(packet, info, sizeof(info));
                    break;
                }
                default: {
                    snprintf(protocol, sizeof(protocol), "IPv6");
                    break;
                }
            }
            break;
        }
        case ETHERTYPE_ARP: { // ARP
            snprintf(protocol, sizeof(protocol), "ARP");
            process_arp(packet, info, sizeof(info));
            break;
        }
        default: {
            snprintf(protocol, sizeof(protocol), "Non-IP");
            strncpy(src_ip, src_mac, sizeof(src_ip));
            strncpy(dst_ip, dst_mac, sizeof(dst_ip));
            break;
        }
    }

    // Exibe as informações no formato Wireshark com alinhamento correto
    printf("%-5d %-10.6f %-39s %-39s %-8s %-6d %s\n",
           packet_count,
           relative_time,
           src_ip,
           dst_ip,
           protocol,
           pkthdr->len,
           info);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Abre a interface de rede para captura
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Erro ao abrir a interface de rede: %s\n", errbuf);
        return 1;
    }

    // Verifica se a interface suporta o modo promíscuo
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface não suporta Ethernet.\n");
        pcap_close(handle);
        return 1;
    }

    // Salva o tempo inicial
    gettimeofday(&start_time, NULL);

    // Cabeçalho da tabela
    printf("%-5s %-10s %-39s %-39s %-8s %-6s %s\n",
           "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info");

    // Inicia a captura de pacotes
    printf("Capturando pacotes na interface 'eth0'. Pressione Ctrl+C para sair.\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    // Libera recursos
    pcap_close(handle);
    return 0;
}
