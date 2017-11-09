/*******************************
 * CPE 464 - Program 1 - trace.c
 * Spring 2017
 *
 * @author Justin Herrera
 ******************************/

#include "trace.h"

/****************************************************************************
 * A helper method to determine the source and destination port when sniffing
 * a TCP or UDP  packet.
 * 
 * @param int port - a port number
 ***************************************************************************/
void evaluate_port(int port)
{
   if (port == HTTP_PORT)
      printf(" Port:  HTTP\n");
   else if (port == TELNET_PORT)
      printf(" Port:  Telnet\n");
   else if (port == FTP_PORT || port == (FTP_PORT + 1))
      printf(" Port:  FTP\n");
   else if (port == POP3_PORT)
      printf(" Port:  POP3\n");
   else if (port == SMTP_PORT)
      printf(" Port:  SMTP\n");
   else if (port == DNS_PORT)
      printf(" Port:  DNS\n");
   else
      printf(" Port:  %d\n", port);
}

/****************************************************************************
 * A helper method to determine if certain flags are set in a TCP packet.
 *
 * @param int flags
 ****************************************************************************/
void evaluate_flags(int flags)
{
   if ((SYN & flags) > 0)
      printf("\t\tSYN Flag: Yes\n");
   else
      printf("\t\tSYN Flag: No\n");
   if ((RST & flags) > 0)
      printf("\t\tRST Flag: Yes\n");
   else
      printf("\t\tRST Flag: No\n");
   if ((FIN & flags) > 0)
      printf("\t\tFIN Flag: Yes\n");
   else
      printf("\t\tFIN Flag: No\n");
   if ((ACK & flags) > 0)
      printf("\t\tACK Flag: Yes\n");
   else
      printf("\t\tACK Flag: No\n");
}

/******************************************************************************
 * A helper method to cacluate the TCP checksum given a packet's tcp pseudo
 * header, and tcp segment. The checksum function takes these two fields and 
 * calculates the checksum over the length.
 *
 * @param const u_char *pkt_data - packet data
 * @param struct tcp_pseudo * tcp_ps - the pseudo header to be used
 * @param unsigned short tcp_checksum - given value (in pkt) of tcp checksum
 *****************************************************************************/
void tcp_checksum_calc(const u_char *pkt_data, struct tcp_pseudo * tcp_ps, 
   unsigned short tcp_checksum)
{
   int len = sizeof(struct tcp_pseudo) + tcp_ps->length;
   uint8_t tcp_buff[len+1];
   unsigned short checksum;

   memset(tcp_buff, 0, len+1);
   memcpy(tcp_buff, tcp_ps, sizeof(struct tcp_pseudo));
   memcpy(tcp_buff + sizeof(struct tcp_pseudo), 
      (pkt_data + ETHERNET_HDR_SIZE + sizeof(struct ip_header)), 
         ntohs(tcp_ps->length));

   checksum = in_cksum((unsigned short *)tcp_buff, len); 

   if (checksum == 0)
      printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(tcp_checksum));
   else
      printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(tcp_checksum)); 
}

/******************************************************************************
 * A helper method to create a tcp pseudo header for a checksum calculation.
 *
 * @param const u_char *pkt_data - packet data
 * @param struct ip_header *ip_header - used for fields in pseudo header
 * @param struct tcp_header *tcp_header - used for tcp segment calculation
 *****************************************************************************/
void evaluate_tcp_checksum(const u_char *pkt_data, struct ip_header *ip_header,
   struct tcp_header* tcp_header)
{
   struct tcp_pseudo * tcp_pseudo = (struct tcp_pseudo *)(pkt_data);

   tcp_pseudo->source_addr = ip_header->source_addr;
   tcp_pseudo->dest_addr = ip_header->dest_addr;
   tcp_pseudo->reserved = 0;
   tcp_pseudo->protocol = ip_header->protocol;
   tcp_pseudo->length = htons(ntohs(ip_header->tot_len) - 
      ((ip_header->ver_hdr_len & 0x0f) * 4));

   tcp_checksum_calc(pkt_data, tcp_pseudo, tcp_header->checksum);
}

/******************************************************************************
 * A helper method to create a tcp struct given the packet data and prints
 * out the required fields.
 *
 * @param const u_char *pkt_data - packet data
 *****************************************************************************/ 
void read_tcp(const u_char *pkt_data) 
{
   struct tcp_header *tcp_header;
   struct ip_header *ip_header;

   ip_header = (struct ip_header *)(pkt_data + ETHERNET_HDR_SIZE);
   tcp_header = (struct tcp_header *)(pkt_data + ETHERNET_HDR_SIZE + 
      ((ip_header->ver_hdr_len & 0x0f) * 4));

   printf("\n\tTCP Header\n"); 
   printf("\t\tSource");

   evaluate_port(ntohs(tcp_header->source_port));

   printf("\t\tDest");

   evaluate_port(ntohs(tcp_header->dest_port));

   printf("\t\tSequence Number: %u\n",(unsigned int)ntohl(tcp_header->seq));
   printf("\t\tACK Number: %u\n", (unsigned int)ntohl(tcp_header->ack_num));
   printf("\t\tData Offset (bytes): %d\n", (tcp_header->hdr_len>> 2) & 0x3c);
  
   evaluate_flags(tcp_header->flags);

   printf("\t\tWindow Size: %d\n", ntohs(tcp_header->window_size));
   
   evaluate_tcp_checksum(pkt_data, ip_header, tcp_header);
}

/******************************************************************************
 * A helper method to read a packet and create a UDP struct and print out
 * the required fields.
 *
 * @param const u_char *pkt_data - packet data
 * @param struct ip_header *ip_header - used to extract ip_header length
 *****************************************************************************/
void read_udp(const u_char *pkt_data, struct ip_header * ip_header)
{
   struct udp_header *udp_header;
   
   udp_header = (struct udp_header *)(pkt_data + ETHERNET_HDR_SIZE + 
      ((ip_header->ver_hdr_len & 0x0f) * 4));

   printf("\n\tUDP Header\n");
   printf("\t\tSource");

   evaluate_port(ntohs(udp_header->source_port));

   printf("\t\tDest");

   evaluate_port(ntohs(udp_header->dest_port)); 
}

/******************************************************************************
 * A helper method to read a packet, create an icmp struct, and print out the 
 * required fields.
 *
 * @param const u_char *pkt_data - packet data
 * @param struct ip_header *ip_header - used to extract length of ip header
 *****************************************************************************/
void read_icmp(const u_char *pkt_data, struct ip_header * ip_header)
{
   struct icmp_header *icmp_header;
   
   icmp_header = (struct icmp_header *)(pkt_data + ETHERNET_HDR_SIZE +
      ((ip_header->ver_hdr_len & 0x0f) *4));

   printf("\n\tICMP Header\n");

   if (icmp_header->type == 0x0)
      printf("\t\tType: Reply\n");
   else if (icmp_header->type == 0x08)
      printf("\t\tType: Request\n"); 
   else
      printf("\t\tType: %d\n", icmp_header->type);
}

/******************************************************************************
 * A method to read a packet, create an IP header struct, print out the 
 * required fields, and call another function determined by the type field.
 *
 * @param const u_char *pkt_data - packet data
 *****************************************************************************/
void read_ip(const u_char *pkt_data)
{
   struct ip_header *ip_header;
   int saved_checksum;

   ip_header = (struct ip_header *)(pkt_data + ETHERNET_HDR_SIZE);

   printf("\n\tIP Header\n");
   printf("\t\tIP Version: %d\n", (ip_header->ver_hdr_len & 0xf0) >> 4);
   printf("\t\tHeader Len (bytes): %d\n", (ip_header->ver_hdr_len&0x0f) * 4);
   printf("\t\tTOS subfields:\n");
   printf("\t\t   Diffserv bits: %d\n", (ip_header->diffserv_ecn) >> 2);
   printf("\t\t   ECN bits: %d\n", (ip_header->diffserv_ecn & 0x03));
   printf("\t\tTTL: %d\n", ip_header->ttl);

   if ((ip_header->protocol) == 0x06) 
      printf("\t\tProtocol: TCP\n");
   else if (ip_header->protocol == 0x01) 
      printf("\t\tProtocol: ICMP\n");
   else if (ip_header->protocol == 0x11)
      printf("\t\tProtocol: UDP\n");
   else 
      printf("\t\tProtocol: Unknown\n");

   saved_checksum = ip_header->checksum;
   ip_header->checksum = 0;
   ip_header->checksum = in_cksum((unsigned short *)ip_header, 
      (ip_header->ver_hdr_len & 0x0f) * 4);
   
   if (saved_checksum == (int)ip_header->checksum)
      printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(saved_checksum));
   else 
      printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(saved_checksum));

   printf("\t\tSender IP: %s\n", inet_ntoa(ip_header->source_addr));
   printf("\t\tDest IP: %s\n", inet_ntoa(ip_header->dest_addr));

   if (ip_header->protocol == 0x06)
      read_tcp(pkt_data);
   if (ip_header->protocol == 0x01)
      read_icmp(pkt_data, ip_header);
   if (ip_header->protocol == 0x11)
      read_udp(pkt_data, ip_header);
}

/******************************************************************************
 * A method to read a packet, create an ARP struct, and print out the required
 * fields.
 *
 * @param const u_char *pkt_data - packet data
 *****************************************************************************/
void read_arp(const u_char *pkt_data)
{
   struct arp_header *arp_header;

   arp_header = (struct arp_header *)(pkt_data + ETHERNET_HDR_SIZE);
   printf("\n\tARP header\n");
   
   if (ntohs(arp_header->opcode) == REQUEST)
      printf("\t\tOpcode: Request\n");
   else
      printf("\t\tOpcode: Reply\n");

   printf("\t\tSender MAC: %s\n", 
      ether_ntoa((struct ether_addr *)&arp_header->sender_mac_addr));
   printf("\t\tSender IP: %s\n", inet_ntoa(arp_header->sender_ip_addr));
   printf("\t\tTarget MAC: %s\n",
      ether_ntoa((struct ether_addr *)&arp_header->target_mac_addr));
   printf("\t\tTarget IP: %s\n\n", inet_ntoa(arp_header->target_ip_addr));

}

/******************************************************************************
 * A method to iteratively read and evaluate each packet in a pcap file.
 *
 * @param pcap_t *p - a pcap file to read from
 *****************************************************************************/
void read_packets(pcap_t *p)
{
   struct pcap_pkthdr *pkt_header;
   struct ethernet_header *ethernet_hdr;
   const u_char *pkt_data;
   int pkt_num = 0;

   while (pcap_next_ex(p, &pkt_header, &pkt_data) >= 0)
   {
      pkt_num++;

      printf("\nPacket number: %d  Packet Len: %d\n", pkt_num, pkt_header->len);
   
      ethernet_hdr = (struct ethernet_header *)(pkt_data);

      printf("\n\tEthernet Header\n");
      printf("\t\tDest MAC: %s\n", 
         ether_ntoa((struct ether_addr *)&ethernet_hdr->dest));
      printf("\t\tSource MAC: %s\n", 
         ether_ntoa((struct ether_addr *)&ethernet_hdr->src)); 
      
      if (ntohs(ethernet_hdr->type) == ETHERTYPE_IP) {
         printf("\t\tType: IP\n");
         read_ip(pkt_data);
      } else if (ntohs(ethernet_hdr->type) == ETHERTYPE_ARP) {
         printf("\t\tType: ARP\n");
         read_arp(pkt_data);
      } else {
         printf("\t\tType: unknown\n"); 
      }
   }
}

/******************************************************************************
 * MAIN METHOD
 *****************************************************************************/
int main(int argc, char * argv[])
{
   pcap_t * p;
   char errbuf[PCAP_ERRBUF_SIZE];

   if (argc != 2) {
      fprintf(stderr, "usage: trace [pcap file]\n");
      exit(-1);
   }

   if ((p = pcap_open_offline(argv[1], errbuf)) == NULL) { 
      fprintf(stderr, "%s\n", errbuf);
      exit(-1);
   }

   read_packets(p);
   
   pcap_close(p);
   return 0;
}
