#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "mrt.h"
#include "mrt-parser-types.h"
#include "bgp-path-attr.h"
#include "bgp-table-dump.h"

bool debug;

void print_hex(void *in, int start, int end)
{
	uint8_t *array = (uint8_t *)in;
	int i;
	for (i = start; i < end; i++) {
		if (i > 0 && i % 8 == 0) {
			printf("\n");
		}
		uint8_t foo = array[i];
		printf("%02x ", foo);
	}
	printf("\n");
}


int parse_peer_index_table(uint8_t *input, struct peer **peer_index_ptr)
{
	int index = 0;
	struct peer *peer_index;

	struct peer_index_header header;
	memcpy(&header, input, sizeof(header));

	header.collector_bgp_id = ntohl(header.collector_bgp_id);
	header.view_name_length = ntohs(header.view_name_length);

	/* the peer index structure includes a variable length
	 * view name, so let's just go off-piste and parse that
	 * out */
	char view_name[header.view_name_length+1];
	memset(view_name, '\0', sizeof(view_name));
	strncpy(view_name, input+sizeof(header), header.view_name_length);

	uint16_t peer_count;
	memcpy(&peer_count, input + sizeof(header) + header.view_name_length, 2);
	peer_count = htons(peer_count);

	index += sizeof(header) + header.view_name_length + sizeof(peer_count);

	if (debug) {
		printf("Peer count: %u\n", peer_count);
		printf("View name length: %u\n", header.view_name_length);
		printf("View name: %s\n", view_name);
	}

	peer_index = (struct peer *)malloc(sizeof(struct peer) * peer_count);
	*peer_index_ptr = peer_index;

	/*
	   The Peer Type field is a bit field that encodes the type of the AS
	   and IP address as identified by the A and I bits, respectively,
	   below.

	       0 1 2 3 4 5 6 7
	      +-+-+-+-+-+-+-+-+
	      | | | | | | |A|I|
	      +-+-+-+-+-+-+-+-+

	      Bit 6: Peer AS number size:  0 = 16 bits, 1 = 32 bits
	      Bit 7: Peer IP Address family:  0 = IPv4,  1 = IPv6

	                         Figure 7: Peer Type Field

	*/
	// 0: IPv4 / 16 bits
	// 1: IPv6 / 16 bits
	// 2: IPv4 / 32 bits
	// 3: IPv6 / 32 bits
	for (int i = 0; i < peer_count; i++) {
		struct peer peer;
		memset(&peer, 0, sizeof(struct peer));
		peer.type = input[index++] & 0x3;

		switch (peer.type) {
		case 0: {
			memcpy(&peer.bgp_id, input+index, sizeof(uint32_t));
			index += 4;
			inet_ntop(AF_INET, input+index, peer.ip_addr, INET6_ADDRSTRLEN);
			index += 4;
			uint16_t tmp;
			memcpy(&tmp, input+index, sizeof(uint16_t));
			peer.asn = htons(tmp);
			index += 2;

			break;
		}
		case 1: {
			memcpy(&peer.bgp_id, input+index, sizeof(uint32_t));
			index += 4;
			inet_ntop(AF_INET6, input+index, peer.ip_addr, INET6_ADDRSTRLEN);
			index += 16;
			uint16_t tmp;
			memcpy(&tmp, input+index, sizeof(uint16_t));
			peer.asn = htons(tmp);
			index += 2;

			break;
		}
		case 2: {
			memcpy(&peer.bgp_id, input+index, sizeof(uint32_t));
			index += 4;
			inet_ntop(AF_INET, input+index, peer.ip_addr, INET6_ADDRSTRLEN);
			index += 4;
			memcpy(&peer.asn, input+index, sizeof(uint32_t));
			peer.asn = htonl(peer.asn);
			index += 4;

			break;
		}
		case 3: {
			memcpy(&peer.bgp_id, input+index, sizeof(uint32_t));
			index += 4;
			inet_ntop(AF_INET6, input+index, peer.ip_addr, INET6_ADDRSTRLEN);
			index += 16;
			memcpy(&peer.asn, input+index, sizeof(uint32_t));
			peer.asn = htonl(peer.asn);
			index += 4;

			break;
		}
		default: {
			printf("ERROR: Parsing peer index type\n");
		}
		}

		memcpy(peer_index+i, &peer, sizeof(struct peer));

		if (debug) {
			printf("Peer idx:%u: %x, %s, %u\n", i, peer.bgp_id, peer.ip_addr, peer.asn);
		}
	}

	return index;
}




// RFC4271, Section 4.1
int parse_bgp_message(uint8_t *input)
{
	int index = 0;

	struct bgp_message_header *header = (struct bgp_message_header *)input;
	index += sizeof(struct bgp_message_header);

	int i;
	for (i = 0; i < 16; i++) {
		uint8_t cmp = 0xff;
		if (memcmp(&header->marker[i], &cmp, sizeof(uint8_t))) {
			fprintf(stderr, "ERROR: Marker on BGP header is not all-ones!\n");
			return index;
		}
	}

	printf("BGP Message length: %x\n", htons(header->length));

	switch (header->type) {
	case BGP_MSG_OPEN: {
		printf("Unhandled: BGP Open\n");
		break;
	}
	case BGP_MSG_UPDATE: {
		uint16_t *withdrawn_len = (uint16_t *)(input+index);
		index += sizeof(uint16_t);

		printf("Withdrawn length: 0x%x bytes\n", htons(*withdrawn_len));
		int i = 0;
		while (i < htons(*withdrawn_len)) {
			uint8_t pfx_len = *(input+index);
			printf("route len: %x\n", pfx_len);

			// bump up to a byte boundary
			while (pfx_len % 8) {
				pfx_len++;
			}

			i+= pfx_len;
			index += pfx_len;
		}

		uint16_t *path_attr_len = (uint16_t *)(input+index);
		index += sizeof(uint16_t);

		printf("Path Attr length: 0x%x\n", htons(*path_attr_len));

		while (i < htons(*path_attr_len)) {
			struct bgp_attr_header attr_header;
			memcpy(&attr_header, input+index, sizeof(attr_header));

			// Bit hacky: header field isn't always the same length.
			i     += sizeof(attr_header.flags) + sizeof(attr_header.code);
			index += sizeof(attr_header.flags) + sizeof(attr_header.code);
			if (attr_header.flags & 0x10) {
				memcpy(&attr_header.len, input+index, sizeof(attr_header.len));
				i     += sizeof(attr_header.len);
				index += sizeof(attr_header.len);
				attr_header.len = ntohs(attr_header.len);
			}
			else {
				attr_header.len = input[index];
				i     += sizeof(input[index]);
				index += sizeof(input[index]);
			}

			if (debug) {
				printf("\n--- BGP ATTRIBUTE HEADER ---\n");
				print_hex(&attr_header, 0, sizeof(attr_header));
				printf(" flags: %x\n",    attr_header.flags);
				printf(" typecode: %x\n", attr_header.code);
				printf(" length: %u\n",   attr_header.len);
			}

			i     += attr_header.len;
			index += attr_header.len;
		}

		break;
	}
	case BGP_MSG_NOTIFICATION: {
		printf("Unhandled: BGP Notification\n");
		break;
	}
	case BGP_MSG_KEEPALIVE: {
		printf("Unhandled: BGP Keepalive\n");
		break;
	}
	}

	return index;
}

int parse_bgp4mp_message_as4(uint8_t *input, int family)
{
	int index = 0;

	struct bgp4mp_state_change *header = (struct bgp4mp_state_change *)input;

	printf("peer ASN: %u\n", htonl(header->asn));
	printf("local ASN: %u\n", htonl(header->local_asn));
	printf("interface ID: %u\n", htons(header->if_idx));
	printf("AF: %u\n", htons(header->af));

	switch (htons(header->af)) {
	case 1: {
		struct bgp4mp_message_as4_v4 *v4header = (struct bgp4mp_message_as4_v4 *)input;
		index += sizeof(struct bgp4mp_message_as4_v4);

		char addr_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &v4header->peer_ip, addr_str, INET_ADDRSTRLEN);
		printf("Peer IP: %s\n", addr_str);
		inet_ntop(AF_INET, &v4header->local_ip, addr_str, INET_ADDRSTRLEN);
		printf("Local IP: %s\n", addr_str);

		parse_bgp_message(input+index);

		break;
	}
	case 2: {
		struct bgp4mp_state_change_v6 *v6header = (struct bgp4mp_state_change_v6 *)input;
		index += sizeof(struct bgp4mp_message_as4_v6);

		char addr_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &v6header->peer_ip, addr_str, INET6_ADDRSTRLEN);
		printf("Peer IP: %s\n", addr_str);
		inet_ntop(AF_INET6, &v6header->local_ip, addr_str, INET6_ADDRSTRLEN);
		printf("Local IP: %s\n", addr_str);

		parse_bgp_message(input+index);

		break;
	}
	default: {
		fprintf(stderr, "Bad AF value in MP4_STATE_CHANGE: %u\n", htons(header->af));
	}
	}

	return index;
}

int parse_bgp4mp_state_change(uint8_t *input, int family)
{
	int index = 0;

	struct bgp4mp_state_change *header = (struct bgp4mp_state_change *)input;

	printf("peer ASN: %u\n", htonl(header->asn));
	printf("local ASN: %u\n", htonl(header->local_asn));
	printf("interface ID: %u\n", htons(header->if_idx));
	printf("AF: %u\n", htons(header->af));

	switch (htons(header->af)) {
	case 1: {
		struct bgp4mp_state_change_v4 *v4header = (struct bgp4mp_state_change_v4 *)input;
		char addr_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &v4header->peer_ip, addr_str, INET_ADDRSTRLEN);
		printf("Peer IP: %s\n", addr_str);
		inet_ntop(AF_INET, &v4header->local_ip, addr_str, INET_ADDRSTRLEN);
		printf("Local IP: %s\n", addr_str);

		printf("Old state: %u\n", htons(v4header->old_state));
		printf("New state: %u\n", htons(v4header->new_state));
		break;
	}
	case 2: {
		struct bgp4mp_state_change_v6 *v6header = (struct bgp4mp_state_change_v6 *)input;
		char addr_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &v6header->peer_ip, addr_str, INET6_ADDRSTRLEN);
		printf("Peer IP: %s\n", addr_str);
		inet_ntop(AF_INET6, &v6header->local_ip, addr_str, INET6_ADDRSTRLEN);
		printf("Local IP: %s\n", addr_str);

		printf("Old state: %u\n", htons(v6header->old_state));
		printf("New state: %u\n", htons(v6header->new_state));
		break;
	}
	default: {
		fprintf(stderr, "Bad AF value in MP4_STATE_CHANGE: %u\n", htons(header->af));
	}
	}


	return index;
}



static volatile sig_atomic_t running = 1;

void interrupt_handler(int _)
{
	(void)_;
	running = 0;
}

void print_help(char *name)
{
	printf("%s: ploughs through MRT files\n", basename(name));
	printf("Options:\n");
	printf("	-f <file>	: Input file (required)\n");
	printf("	-d		: Turns on debugging.\n");
	printf("	-s		: Output spec: [0x]aspath, [0x]communities\n");
	printf("	-h		: Print this help then exit.\n");
	printf("	-4		: Print only lines with IPv4 announcements.\n");
	printf("	-6		: Print only lines with IPv6 announcements.\n");
}

void set_spec_default(struct spec *spec)
{
	spec->aspath = true;
	spec->aspath_hex = false;
	spec->communities = true;
	spec->communities_hex = false;
}
void parse_spec(char *arg, struct spec *spec)
{
	char *tmp = strtok(arg, " ,");


	while (tmp != NULL) {

		printf("looping\n");

		if (!strcmp(tmp, "aspath")) {
			spec->aspath = true;
			spec->aspath_hex = false;
		}
		if (!strcmp(tmp, "0xaspath")) {
			spec->aspath = true;
			spec->aspath_hex = true;
		}
		if (!strcmp(tmp, "communities")) {
			spec->communities = true;
			spec->communities_hex = false;
		}
		if (!strcmp(tmp, "0xcommunities")) {
			spec->communities = true;
			spec->communities_hex = true;
		}

		tmp = strtok(NULL, " ,");
	}

	printf("spec: %u %u %u %u\n", spec->aspath, spec->aspath_hex, spec->communities, spec->communities_hex);
}

int main(int argc, char *argv[])
{
	signal(SIGINT, interrupt_handler);

	gzFile file;
	debug  = false;
	bool parsev4 = false;
	bool parsev6 = false;
	bool parse_peerindex = true;

	struct spec spec;
	set_spec_default(&spec);

	struct peer *peer_index = NULL;

	int opt;
	while ((opt = getopt(argc, argv, "46df:s:h")) != -1) {
		switch (opt) {
		case '4': {
			parsev4 = true;
			break;
		}
		case '6': {
			parsev6 = true;
			break;
		}
		case 'd': {
			debug = true;
			fprintf(stderr, "Enabled debug\n");
			break;
		}
		case 'f': {
			file = gzopen(optarg, "r");
			if (file == NULL) {
				fprintf(stderr, "Could not open file; error: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
			break;
		}
		case 's': {
			parse_spec(optarg, &spec);
			break;
		}
		default:
		case 'h': {
			print_help(argv[0]);
			exit(EXIT_FAILURE);
		}
		}
	}

	if (!parsev4 && !parsev6) {
		parsev4 = true;
		parsev6 = true;
	}

	struct mrt_header header;
	while (running && gzread(file, &header, sizeof(struct mrt_header)) == sizeof(struct mrt_header)) {
		header.ts      = ntohl(header.ts);
		header.type    = ntohs(header.type);
		header.subtype = ntohs(header.subtype);
		header.length  = ntohl(header.length);

		if (debug) {
			printf("\n--- MRT HEADER ---\n");
			print_hex(&header, 0, sizeof(header));
			printf(" ts: %u\n",      header.ts);
			printf(" type: %u\n",    header.type);
			printf(" subtype: %u\n", header.subtype);
			printf(" length: %u\n",  header.length);
			printf("\n");
		}

		switch (header.type) {
		case MRT_TABLE_DUMP_V2: {
			switch (header.subtype) {
			case TABLE_DUMP_V2_PEER_INDEX_TABLE: {
				if (parse_peerindex) {
					uint8_t *input = (uint8_t *)malloc(header.length);
					gzread(file, input, header.length);
					uint32_t bytes_parsed = parse_peer_index_table(input, &peer_index);
					free(input);

					if (bytes_parsed != header.length) {
						printf("Error: parsed %u bytes from a header length %u\n",
							bytes_parsed, header.length);
						exit(EXIT_FAILURE);
					}
				}
				break;
			}
			case TABLE_DUMP_V2_RIB_IPV4_UNICAST: {
				if (parsev4) {
					uint8_t *input = (uint8_t *)malloc(header.length);
					gzread(file, input, header.length);
					uint32_t bytes_parsed = parse_ipvN_unicast(&spec, false, peer_index, input, header.length, header.ts, header.subtype);
					free(input);

					if (bytes_parsed != header.length) {
						printf("Error: parsed %u bytes from a header length %u\n",
							bytes_parsed, header.length);
						exit(EXIT_FAILURE);
					}
				}
				else {
					gzseek(file, header.length, SEEK_CUR);
				}
				break;
			}
			case TABLE_DUMP_V2_RIB_IPV6_UNICAST: {
				if (parsev6) {
					uint8_t *input = (uint8_t *)malloc(header.length);
					gzread(file, input, header.length);
					uint32_t bytes_parsed = parse_ipvN_unicast(&spec, false, peer_index, input, header.length, header.ts, header.subtype);
					free(input);

					if (bytes_parsed != header.length) {
						printf("Error: parsed %u bytes from a header length %u\n",
							bytes_parsed, header.length);
						exit(EXIT_FAILURE);
					}
				}
				else {
					gzseek(file, header.length, SEEK_CUR);
				}
				break;
			}
			case TABLE_DUMP_V2_RIB_IPV4_UNICAST_ADDPATH: {
				if (parsev4) {
					uint8_t *input = (uint8_t *)malloc(header.length);
					gzread(file, input, header.length);
					uint32_t bytes_parsed = parse_ipvN_unicast(&spec, true, peer_index, input, header.length, header.ts, header.subtype);
					free(input);

					if (bytes_parsed != header.length) {
						printf("Error: parsed %u bytes from a header length %u\n",
							bytes_parsed, header.length);
						exit(EXIT_FAILURE);
					}
				}
				else {
					gzseek(file, header.length, SEEK_CUR);
				}
				break;
			}
			case TABLE_DUMP_V2_RIB_IPV6_UNICAST_ADDPATH: {
				if (parsev6) {
					uint8_t *input = (uint8_t *)malloc(header.length);
					gzread(file, input, header.length);
					uint32_t bytes_parsed = parse_ipvN_unicast(&spec, true, peer_index, input, header.length, header.ts, header.subtype);
					free(input);

					if (bytes_parsed != header.length) {
						printf("Error: parsed %u bytes from a header length %u\n",
							bytes_parsed, header.length);
						exit(EXIT_FAILURE);
					}
				}
				else {
					gzseek(file, header.length, SEEK_CUR);
				}
				break;
			}
			default: {
				if (debug) {
					printf("Unhandled MRT_TABLE_DUMP_V2 subtype %u\n", header.subtype);
				}
				gzseek(file, header.length, SEEK_CUR);
			}
			}
			break;
		}
		case MRT_BGP4MP: {
			switch (header.subtype) {
			case BGP4MP_STATE_CHANGE: {
				uint8_t *input = (uint8_t *)malloc(header.length);
				gzread(file, input, header.length);
				uint32_t bytes_parsed = parse_bgp4mp_state_change(input, header.subtype);
				free(input);
				break;
			}
			case BGP4MP_MESSAGE: {
				printf("Unhandled BGP4MP_MESSAGE\n");
				gzseek(file, header.length, SEEK_CUR);
				break;
			}
			case BGP4MP_MESSAGE_AS4: {
				uint8_t *input = (uint8_t *)malloc(header.length);
				gzread(file, input, header.length);
				uint32_t bytes_parsed = parse_bgp4mp_message_as4(input, header.subtype);
				free(input);
				break;
			}
			case BGP4MP_STATE_CHANGE_AS4: {
				printf("Unhandled BGP4MP_STATE_CHANGE_AS4\n");
				gzseek(file, header.length, SEEK_CUR);
				break;
			}
			case BGP4MP_MESSAGE_LOCAL: {
				printf("Unhandled BGP4MP_MESSAGE_LOCAL\n");
				gzseek(file, header.length, SEEK_CUR);
				break;
			}
			case BGP4MP_MESSAGE_AS4_LOCAL: {
				printf("Unhandled BGP4MP_MESSAGE_AS4_LOCAL\n");
				gzseek(file, header.length, SEEK_CUR);
				break;
			}
			default: {
				if (debug) {
					printf("Unhandled BGP4MP subtype %u\n", header.subtype);
				}
				gzseek(file, header.length, SEEK_CUR);
			}
			}
			break;
		}
		default: {
			if (debug) {
				fprintf(stderr, "Unhandled type %u\n", header.type);
			}
		}
		}
	}
	if (peer_index != NULL) {
		free(peer_index);
		peer_index = NULL;
	}
	gzclose(file);

	return EXIT_SUCCESS;
}

