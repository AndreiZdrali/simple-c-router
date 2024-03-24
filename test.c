#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define MAX_RTABLE_SIZE 80000
#define MAX_ARP_SIZE 1000

//TODO: sa fac un trie pentru tabela de rutare - https://github.com/dzolo/lpm/blob/master/trie.c
struct route_table_entry *get_best_route(uint32_t dest_ip, struct route_table_entry *rtable, int rtable_size)
{
	struct route_table_entry *best_route = NULL;
	int max_mask = -1;

	for (int i = 0; i < rtable_size; i++) {
		if ((dest_ip & rtable[i].mask) == rtable[i].prefix) {
			if (rtable[i].mask > max_mask) {
				max_mask = rtable[i].mask;
				best_route = &rtable[i];
			}
		}
	}

	return best_route;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// citim tabla de rutare
	struct route_table_entry* route_table = malloc(MAX_RTABLE_SIZE * sizeof(struct route_table_entry));
	int rtable_size = read_rtable(argv[1], route_table);

	// citim tabela statica ARP
	struct arp_table_entry* arp_table = malloc(MAX_ARP_SIZE * sizeof(struct arp_table_entry));
	int arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// daca e IPV4
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV4) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			uint32_t my_ip;
			inet_pton(AF_INET, get_interface_ip(interface), &my_ip);

			// daca e pentru mine, trb schmbata comparatia
			if (ntohs(ip_hdr->daddr) == my_ip) {
				// TODO: vf daca e ICMP, altfel drop
			}
        }
	}
}

