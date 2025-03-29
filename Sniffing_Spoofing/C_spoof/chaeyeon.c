#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"  // TCP, UDP, ICMP 구조체 있는 헤더

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  // MAC 주소 출력
  printf("\n=== New Packet ===\n");
  printf("Ethernet: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
    eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

  if (ntohs(eth->ether_type) == 0x0800) { // IP 패킷인 경우
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    printf("IP: %s -> %s\n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));

    if (ip->iph_protocol == IPPROTO_TCP) {
      printf("Protocol: TCP\n");

      // IP 헤더 길이 계산 (단위: 4바이트 → byte 단위로 변환)
      int ip_header_len = ip->iph_ihl * 4;
      struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

      printf("TCP: %u -> %u\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));

      // Payload (메시지) 출력 (옵션)
      const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + TH_OFF(tcp) * 4;
      int payload_len = ntohs(ip->iph_len) - ip_header_len - TH_OFF(tcp) * 4;

      if (payload_len > 0) {
        printf("Message: ");
        for (int i = 0; i < payload_len && i < 16; i++) { // 최대 16바이트만 출력
          printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
      }
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);  // 본인 NIC 이름으로 수정!
  if (handle == NULL) {
      fprintf(stderr, "Couldn't open device: %s\n", errbuf);
      return 2;
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
      return 2;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
      return 2;
  }

  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle);
  return 0;
}
