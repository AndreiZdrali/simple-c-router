#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdarg.h>

#define DEBUG 1

#define MAX_RTABLE_SIZE 80000
#define MAX_ARP_SIZE 1000

#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02

void debug_printf(const char* format, ...)
{
	if (DEBUG) {
		va_list args;
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	}
}

void printBits(size_t const size, void const * const ptr)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;
    
    for (i = size-1; i >= 0; i--) {
		debug_printf(".");
        for (j = 7; j >= 0; j--) {
            byte = (b[i] >> j) & 1;
            debug_printf("%u", byte);
        }
    }
    debug_printf("\n");
}

void print_ip(uint32_t ip)
{
	char *ip_str = malloc(16);
	inet_ntop(AF_INET, &ip, ip_str, 16);
	debug_printf("%s\n", ip_str);
	free(ip_str);
}

//TODO: sa fac un trie pentru tabela de rutare - https://github.com/dzolo/lpm/blob/master/trie.c
struct route_table_entry *get_best_route(uint32_t dest_ip, struct route_table_entry *rtable, int rtable_size)
{
	struct route_table_entry *best_route = NULL;
	int max_mask = 0;

	for (int i = 0; i < rtable_size; i++) {
		if ((dest_ip & rtable[i].mask) == rtable[i].prefix) {
			if (ntohl(rtable[i].mask) > max_mask) {
				max_mask = ntohl(rtable[i].mask);
				best_route = &rtable[i];
			}
		}
	}

	return best_route;
}

int main(int argc, char *argv[])
{
	//setvbuf(stdout, NULL, _IONBF, 0);
	
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// citim tabla de rutare
	struct route_table_entry* route_table = malloc(MAX_RTABLE_SIZE * sizeof(struct route_table_entry));
	int rtable_size = read_rtable(argv[1], route_table);

	// conversie din network order in host order
	// for (int i = 0; i < rtable_size; i++) {
	// 	route_table[i].prefix = ntohl(route_table[i].prefix);
	// 	route_table[i].next_hop = ntohl(route_table[i].next_hop);
	// 	route_table[i].mask = ntohl(route_table[i].mask);
	// }

	// citim tabela statica ARP
	struct arp_table_entry* arp_table = malloc(MAX_ARP_SIZE * sizeof(struct arp_table_entry));
	int arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	for (int i = 0; i < 3; i++)
		debug_printf("Interface %d: %s\n", i, get_interface_ip(i));

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		debug_printf("=============================================\n");
		debug_printf("Received packet on interface %d\n", interface);

		uint32_t my_ip;
		inet_pton(AF_INET, get_interface_ip(interface), &my_ip);

		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// daca e IPv4
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV4) {
			debug_printf("Received IPv4 packet\n");

			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			char* dest_ip_str = malloc(16);
			inet_ntop(AF_INET, &ip_hdr->daddr, dest_ip_str, 16);
			debug_printf("Destination IP: %s\n", dest_ip_str);
			free(dest_ip_str);

			// daca e pentru mine, trb schmbata comparatia
			if (ip_hdr->daddr == my_ip) {
				// TODO: vf daca e ICMP, altfel drop
			}

			// verific checksum
			uint16_t check = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			if (check != checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4)) {
				debug_printf("Failed checksum \n");
				continue;
			}

			debug_printf("TTL: %d -> %d\n", ip_hdr->ttl, ip_hdr->ttl - 1);
			// verific ttl
			if (ip_hdr->ttl <= 1) {
				// TODO: trimit ICMP TTL Exceeded
				debug_printf("TTL exceeded\n");
				continue;
			}

			// decrementez ttl
			ip_hdr->ttl--;

			// caut in tabela de rutare
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, route_table, rtable_size);

			// daca nu gasesc ruta
			if (best_route == NULL) {
				// TODO: trimit ICMP Destination Unreachable
				debug_printf("No route found\n");
				continue;
			}

			// ii dam reverse in network order pt ca tabela e in host order
			int next_hop_hw = htonl(best_route->next_hop);
			debug_printf("Next hop: "); print_ip(next_hop_hw);

			// actualizez checksum
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, ip_hdr->ihl * 4));

			// mac-ul sursa devine interfata pe care trimitem
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			debug_printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

			// mac-ul destinatie devine mac-ul next_hop-ului
			for (int i = 0; i < arp_table_len; i++) {
				if (arp_table[i].ip == best_route->next_hop) {
					memcpy(eth_hdr->ether_dhost, arp_table[i].mac, 6);
					break;
				}
			}
			debug_printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

			// TODO: sa calculez lungimea?

			// trimit pachetul
			send_to_link(best_route->interface, buf, len);

			debug_printf("Sent packet on interface %d\n", best_route->interface);
		}

		// TODO: SA REPAR GUNOIUL ASTA
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			// daca e request
			if (ntohs(arp_hdr->op) == ARP_REQUEST) {
				debug_printf("Received ARP request\n");
				// daca e pentru mine
				if (arp_hdr->tpa == my_ip) {
					// trimit reply
					struct arp_header *arp_hdr_reply = (struct arp_header *)(buf + sizeof(struct ether_header));

					// schimb mac-urile
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					get_interface_mac(interface, eth_hdr->ether_shost);

					// schimb opcode-ul
					arp_hdr_reply->op = htons(ARP_REPLY);

					// schimb ip-urile
					arp_hdr_reply->tpa = arp_hdr->spa;
					arp_hdr_reply->spa = arp_hdr->tpa;

					// schimb mac-urile
					memcpy(arp_hdr_reply->tha, arp_hdr->sha, 6);
					get_interface_mac(interface, arp_hdr_reply->sha);

					// trimit pachetul
					send_to_link(interface, buf, len);
				}
			}

			// daca e reply
			if (ntohs(arp_hdr->op) == ARP_REPLY) {
				debug_printf("Received ARP reply\n");
				// adaug in tabela ARP
				//add_arp_entry(arp_hdr->spa, arp_hdr->sha);
			}
		}
	}
}

