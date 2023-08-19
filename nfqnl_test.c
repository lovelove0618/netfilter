#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* Define the harmful site's host name */
static const char* HARMFUL_HOST = NULL;

/* returns packet id */
static u_int32_t print_pkt(struct nfq_data* tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr* ph;
	struct nfqnl_msg_packet_hw* hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char* data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen - 1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen - 1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d\n", ret);

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
	struct nfq_data* nfa, void* data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");

	// Extract payload data
	unsigned char* payload_data;
	int payload_len = nfq_get_payload(nfa, &payload_data);

	if (payload_len >= 20 && payload_data[9] == 6) {
		// Check if it's an IPv4 packet and the protocol is TCP
		int ip_header_len = (payload_data[0] & 0xF) * 4;
		int tcp_header_len = (payload_data[ip_header_len + 12] >> 4) * 4;
		int total_header_len = ip_header_len + tcp_header_len;

		// Check if it's an HTTP packet (port 80)
		if (payload_len >= total_header_len + 4 &&
			payload_data[ip_header_len + 2] == 0 &&
			payload_data[ip_header_len + 3] == 80) {

			// Search for the "Host" field in HTTP header
			unsigned char* host_ptr = payload_data + total_header_len;
			int host_len = 0;

			for (int i = 0; i < payload_len - total_header_len - 4; ++i) {
				if (host_ptr[i] == 'H' && host_ptr[i + 1] == 'o' &&
					host_ptr[i + 2] == 's' && host_ptr[i + 3] == 't') {
					host_ptr += i + 6;  // Skip "Host: "
					host_len = 0;
					while (host_ptr[host_len] != '\r' && host_ptr[host_len] != '\n') {
						++host_len;
					}
					break;
				}
			}

			// Check if the extracted Host field matches the harmful host
			if (host_len == strlen(HARMFUL_HOST) &&
				strncmp(host_ptr, HARMFUL_HOST, host_len) == 0) {
				printf("Blocking packet to harmful site: %s\n", HARMFUL_HOST);
				return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
			}
		}
	}

	// If no harmful condition is met, accept the packet
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}



int main(int argc, char** argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <host>\n", argv[0]);
		return 1;
	}

	HARMFUL_HOST = argv[1];

	struct nfq_handle* h;
	struct nfq_q_handle* qh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	// Check if rule already exists before adding
	if (system("iptables -C INPUT -j NFQUEUE --queue-num 0") != 0) {
		// Rule does not exist, so add it
		system("iptables -A INPUT -j NFQUEUE --queue-num 0");
	}

	if (system("iptables -C OUTPUT -j NFQUEUE --queue-num 0") != 0) {
		// Rule does not exist, so add it
		system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

