#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "mrt.h"

static bool debug;

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

/*
rfc4760
        +---------------------------------------------------------+
        | Address Family Identifier (2 octets)                    |
        +---------------------------------------------------------+
        | Subsequent Address Family Identifier (1 octet)          |
        +---------------------------------------------------------+
        | Length of Next Hop Network Address (1 octet)            |
        +---------------------------------------------------------+
        | Network Address of Next Hop (variable)                  |
        +---------------------------------------------------------+
        | Reserved (1 octet)                                      |
        +---------------------------------------------------------+
        | Network Layer Reachability Information (variable)       |
        +---------------------------------------------------------+
*/
int parse_bgp_path_attr_mp_reach_nlri(char *buffer, int buffer_len, uint8_t *input, int len)
{
	int index = 0;
	struct attr_mp_reach_nlri header;
	memcpy(&header, input+index, sizeof(header));
	header.afi = htons(header.afi);

	index += sizeof(header);

	if (debug) {
		printf("\n--- BGP PATH ATTR MP REACH NLRI (len:%u/%u) ---\n", len, header.nh_len);
		print_hex(&header, 0, sizeof(header));
		printf(" afi :%u\n", header.afi);
		printf(" safi:%u\n", header.safi);
		printf(" len (next hop):%u\n", header.nh_len);
	}

	switch (header.afi) {
	case 1: {
		index += header.nh_len;
		break;
	}
	case 2: {
		char addr_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, input+index, addr_str, INET6_ADDRSTRLEN);
		index += header.nh_len;

		break;
	}
	default: {
		fprintf(stdout, "Unknown AF type in NLRI information: %u\n", header.afi);
		return index;
	}
	}

	// reserved octet
	//printf("[%3u] DEBUG: Skipping reserved octect at pos %u\n", index, index);
	index += 1;

	char *buffer_idx = buffer;
	int remaining    = buffer_len;

	while (index < len) {
		uint8_t nlri_len;
		memcpy(&nlri_len, input+index, 1);
		index += 1;

		if (debug) {
			printf("--- NLRI ---\n");
			printf(" nlri_len:%u\n",      nlri_len);
		}

		if (nlri_len == 0) {
			continue;
		}

		switch (header.afi) {
		case 1: {
			char addr_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, input+index, addr_str, INET_ADDRSTRLEN);

			int n = snprintf(buffer_idx, remaining, "%s/%u", addr_str, nlri_len);
			buffer_idx += n;
			remaining  -= n;


			int16_t len = 0, i = nlri_len;
			while (i > 0) {
				len++; i-=8;
			}

			index += len;
			break;
		}
		case 2: {
			char addr_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, input+index, addr_str, INET6_ADDRSTRLEN);

			int n = snprintf(buffer_idx, remaining, "%s/%u", addr_str, nlri_len);
			buffer_idx += n;
			remaining  -= n;

			int16_t len = 0, i = nlri_len;
			while (i > 0) {
				len++; i-=8;
			}

			index += len;
			break;
		}
		default: {
			fprintf(stdout, "[%3u] Unknown AF type in NLRI information: %u\n", index, header.afi);
			return index;
		}
		}
	}

	return index;
}

int parse_bgp_path_attr_community(char *buffer, int buffer_len, uint8_t *input, int len)
{
	if (len % 4 != 0) {
		fprintf(stderr, "Malformed community of length %u\n", len);
	}

	int idx = 0;
	char *buffer_idx = buffer;
	int remaining = buffer_len;
	while (idx < len) {
		if (idx != 0) {
			snprintf(buffer_idx, remaining, " ");
			buffer_idx ++;
			remaining  --;
		}
		uint16_t *a, *b;
		a = (uint16_t *)(input+idx);
		idx += 2;
		b = (uint16_t *)(input+idx);
		idx += 2;

		snprintf(buffer_idx, remaining, "%04x:%04x", *a, *b);
		buffer_idx += 9;
		remaining  -= 9;
	}

	return len;
}

int parse_bgp_path_attr_nexthop(char *buffer, int remaining, uint8_t *input, int len)
{
	return len;
}

/*
   1 byte type, 1 byte count; V2 ASNs are 4 bytes; N of these entries up
   to 'len' bytes in the attribute
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
      |    type == ASPATH_AS_SE[TQ]   |    Count = num ASNs           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
int parse_bgp_path_attr_aspath(char *buffer, int remaining, uint8_t *input, int len)
{
	int idx = 0;
	char *buffer_idx = buffer;

	while (idx < len) {
		struct attr_as_path_header header;
		memcpy(&header, input+idx, sizeof(header));
		idx += sizeof(header);

		if (debug) {
			printf("\n--- BGP PATH ATTR AS PATH ---\n");
			print_hex(&header, 0, sizeof(header));
			printf(" type:%u\n",  header.type);
			printf(" count:%u\n", header.count);
		}

		uint32_t *asn;
		int hop_count = 0;
		int n;
		if (header.type ==  ASPATH_AS_SET) {
			while (hop_count < header.count) {
				asn = (uint32_t *)(input+idx);
				if (hop_count == 0) {
					snprintf(buffer_idx, remaining, " {");
					buffer_idx += 2;
					remaining  -= 2;
				}
				else {
					snprintf(buffer_idx, remaining, ",");
					buffer_idx++;
					remaining--;
				}
				n = snprintf(buffer_idx, remaining, "%u", htonl(*asn));
				buffer_idx += n;
				remaining  -= n;
				idx += sizeof(uint32_t);
				hop_count++;
			}
			snprintf(buffer_idx, remaining, "}");
			buffer_idx++;
			remaining--;
		}
		else if (header.type == ASPATH_AS_SEQ) {
			while (hop_count < header.count) {
				asn = (uint32_t *)(input+idx);
				if (hop_count != 0) {
					snprintf(buffer_idx, remaining, " ");
					buffer_idx++;
					remaining--;
				}
				n = snprintf(buffer_idx, remaining, "%u", htonl(*asn));
				buffer_idx += n;
				remaining  -= n;
				idx += sizeof(uint32_t);
				hop_count++;
			}
		}
	}

	return idx;
}


/*
   2 bytes, 4 bytes, 2 bytes:
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
      |    Peer Index =  15           |    Originated ...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           ... time                   | Attribute Length              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
int parse_entry(uint8_t *input)
{
	struct table_dump_v2_ipv6_unicast_header header;
	uint16_t index = 0;

	memcpy(&header, input, sizeof(header));
	header.attr_len = htons(header.attr_len);

	index += sizeof(header);

	if (debug) {
		header.peer_idx = htons(header.peer_idx);
		header.orig_ts  = htonl(header.orig_ts);

		printf("\n--- TABLE_DUMP_V2 IPv6 UNICAST ENTRY HEADER ---\n");
		print_hex(&header, 0, sizeof(header));
		printf(" peer_index:%u\n", header.peer_idx);
		printf(" orig_ts: %u\n",   header.orig_ts);
		printf(" attr_len: %lu + %u\n", sizeof(header), header.attr_len);
	}


	/* Common entries */
	uint16_t mask = BGP_PATH_ATTR_ORIGIN_MASK |
			BGP_PATH_ATTR_ASPATH_MASK |
			BGP_PATH_ATTR_NEXTHOP_MASK |
			BGP_PATH_ATTR_EXITDISC_MASK |
			BGP_PATH_ATTR_COMMUNITY_MASK |
			BGP_PATH_ATTR_MP_REACH_NLRI_MASK;

	int buf_len = 262144;

	char aspath_buffer[buf_len];
	aspath_buffer[0] = '\0';
	char nexthop_buffer[buf_len];
	nexthop_buffer[0] = '\0';
	char communities_buffer[buf_len];
	communities_buffer[0] = '\0';


	/* parse BGP attributes */
	while (index < sizeof(header) + header.attr_len) {
		struct bgp_attr_header attr_header;
		memcpy(&attr_header, input+index, sizeof(attr_header));

		// Bit hacky: header field isn't always the same length.
		index += sizeof(attr_header.flags) + sizeof(attr_header.code);
		if (attr_header.flags & 0x10) {
			memcpy(&attr_header.len, input+index, sizeof(attr_header.len));
			index += sizeof(attr_header.len);
			attr_header.len = ntohs(attr_header.len);
		}
		else {
			attr_header.len = input[index];
			index += sizeof(input[index]);
		}

		if (debug) {
			printf("\n--- BGP ATTRIBUTE HEADER ---\n");
			print_hex(&attr_header, 0, sizeof(attr_header));
			printf(" flags: %x\n",    attr_header.flags);
			printf(" typecode: %x\n", attr_header.code);
			printf(" length: %u\n",   attr_header.len);
		}

		switch (attr_header.code) {
		case BGP_PATH_ATTR_ORIGIN: {
			if (debug) {
				printf("Skipping PATH_ATTR_ORIGIN type (%u)\n", attr_header.code);
			}
			/* Clear mask */
			mask -= BGP_PATH_ATTR_ORIGIN_MASK;
			break;
		}
		case BGP_PATH_ATTR_ASPATH: {
		/* Columnar output needs to be consistent; if we expect a column in the
		 * mask but it's not present in the data, add columns */
			int rc = parse_bgp_path_attr_aspath(aspath_buffer, buf_len, input+index, attr_header.len);
			if (rc != attr_header.len) {
				fprintf(stderr, "AS_PATH attribute incorrect length: parsed %u, expected %u\n",
					rc, attr_header.len);
			}
			break;
		}
		case BGP_PATH_ATTR_NEXTHOP: {
			int rc = parse_bgp_path_attr_nexthop(nexthop_buffer, buf_len, input+index, attr_header.len);
			if (rc != attr_header.len) {
				fprintf(stderr, "NEXTHOP attribute incorrect length: parsed %u, expected %u\n",
					rc, attr_header.len);
			}
			break;
		}
		case BGP_PATH_ATTR_EXITDISC: {
			if (debug) {
				printf("Skipping PATH_ATTR_EXIT_DISC type (%u)\n", attr_header.code);
			}
			break;
		}
		case BGP_PATH_ATTR_LOCALPREF: {
			if (debug) {
				printf("Skipping PATH_ATTR_LOCALPREF type (%u)\n", attr_header.code);
			}
			break;
		}
		case BGP_PATH_ATTR_ATOM_AGG: {
			if (debug) {
				printf("Skipping PATH_ATTR_ATOM_AGG type (%u)\n", attr_header.code);
			}
			break;
		}
		case BGP_PATH_ATTR_AGGREGATOR: {
			if (debug) {
				printf("Skipping PATH_ATTR_AGGREGATOR type (%u)\n", attr_header.code);
			}
			break;
		}
		case BGP_PATH_ATTR_COMMUNITY: {
			int rc = parse_bgp_path_attr_community(communities_buffer, buf_len, input+index, attr_header.len);
			if (rc != attr_header.len) {
				fprintf(stderr, "COMMUNITY attribute incorrect length: parsed %u, expected %u\n",
					rc, attr_header.len);
			}
			break;
		}
		case BGP_PATH_ATTR_MP_REACH_NLRI: {
//			int rc = parse_bgp_path_attr_mp_reach_nlr
//			if (rc != attr_header.len) {
//				printf("MP_REACH_NLRI attribute incorrect length: parsed %u, expected %u\n",
//					rc, attr_header.len);
//				fprintf(stderr, "MP_REACH_NLRI attribute incorrect length: parsed %u, expected %u\n",
//					rc, attr_header.len);
//			}
//			//mask -= BGP_PATH_ATTR_MP_REACH_NLRI_MASK;
			break;
		}
		default: {
			if (debug) {
				printf("Skipping type %u\n", attr_header.code);
			}
		}
		}

		index += attr_header.len;
	}

	printf("||%s|%s||%s\n", aspath_buffer, nexthop_buffer, communities_buffer);

	if (index != sizeof(header) + header.attr_len) {
		printf("Warning: bad length detected in IPv6 unicast entry: %u != %u\n",
			index, header.attr_len);
		exit(EXIT_FAILURE);
	}

	return index;
}

/*
  4 bytes, 1 byte, N bytes, 2 bytes:

  This one's a bit awkward.

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Sequence Number                          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Preflen     |                Prefix  ....
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            ....       |    Entry Count                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
int parse_ipvN_unicast(uint8_t *input, int family)
{
	int index = 0;

	uint8_t  pfx_len;
	char out_str[INET6_ADDRSTRLEN];
	uint16_t entries_count;

	index += sizeof(uint32_t);

	pfx_len = input[index];
	index += sizeof(pfx_len);

	uint8_t num_bytes = 0;
	int tmp = pfx_len;
	while (tmp > 0) {num_bytes++; tmp-=8;}

	if (family == TABLE_DUMP_V2_RIB_IPV6_UNICAST) {
		struct in6_addr *addr;
		addr = (struct in6_addr *)(input+index);
		inet_ntop(AF_INET6, addr, out_str, INET6_ADDRSTRLEN);
	}
	else if (family == TABLE_DUMP_V2_RIB_IPV4_UNICAST) {
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(struct sockaddr_in));
		memcpy(&addr.sin_addr, input+index, num_bytes);
		memset(out_str, 0, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &addr.sin_addr, out_str, INET_ADDRSTRLEN);
	}

	index += num_bytes;

	memcpy(&entries_count, input+index, sizeof(entries_count));
	entries_count = ntohs(entries_count);
	index += sizeof(entries_count);

	uint16_t i;
	for (i = 0; i < entries_count; i++) {
		printf("%s/%u", out_str, pfx_len);
		index += parse_entry(input+index);
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
			//uint8_t buffer[128];
			//memset(buffer, 0, 128);
			//memcpy(buffer, input+index, pfx_len);
			//int j = 0;
			//for (j = 0; i < 128; j++) {
			//	printf("%x ", buffer[j]);
			//}
			//printf("\n");

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

void print_help(char *name)
{
	printf("%s: ploughs through MRT files\n", basename(name));
	printf("Options:\n");
	printf("	-f <file>	: Input file (required)\n");
	printf("	-d		: Turns on debugging.\n");
	printf("	-h		: Print this help then exit.\n");
}


int main(int argc, char *argv[])
{
	gzFile file;
	debug  = false;
	bool parsev4 = false;
	bool parsev6 = false;

	int opt;
	while ((opt = getopt(argc, argv, "46df:h")) != -1) {
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
	while (gzread(file, &header, sizeof(struct mrt_header)) == sizeof(struct mrt_header)) {
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
			case TABLE_DUMP_V2_RIB_IPV4_UNICAST: {
				if (parsev4) {
					uint8_t *input = (uint8_t *)malloc(header.length);
					gzread(file, input, header.length);
					uint32_t bytes_parsed = parse_ipvN_unicast(input, header.subtype);
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
					uint32_t bytes_parsed = parse_ipvN_unicast(input, header.subtype);
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
					fprintf(stderr, "Unhandled subtype %u\n", header.subtype);
				}
				gzseek(file, header.length, SEEK_CUR);
			}
			}
			break;
		}
		case MRT_BGP4MP: {
			switch (header.subtype) {
			case BGP4MP_STATE_CHANGE: {
				printf("LOOKS OK 1\n");
				uint8_t *input = (uint8_t *)malloc(header.length);
				gzread(file, input, header.length);
				uint32_t bytes_parsed = parse_bgp4mp_state_change(input, header.subtype);
				free(input);
				//gzseek(file, header.length, SEEK_CUR);
				break;
			}
			case BGP4MP_MESSAGE: {
				printf("LOOKS OK 2\n");
				gzseek(file, header.length, SEEK_CUR);
				break;
			}
			case BGP4MP_MESSAGE_AS4: {
				printf("LOOKS OK 3\n");
				uint8_t *input = (uint8_t *)malloc(header.length);
				gzread(file, input, header.length);
				uint32_t bytes_parsed = parse_bgp4mp_message_as4(input, header.subtype);
				free(input);
				//gzseek(file, header.length, SEEK_CUR);
				break;
			}
			case BGP4MP_STATE_CHANGE_AS4: {
				printf("LOOKS OK 4\n");
				gzseek(file, header.length, SEEK_CUR);
				break;
			}
			case BGP4MP_MESSAGE_LOCAL: {
				printf("LOOKS OK 5\n");
				gzseek(file, header.length, SEEK_CUR);
				break;
			}
			case BGP4MP_MESSAGE_AS4_LOCAL: {
				printf("LOOKS OK 6\n");
				gzseek(file, header.length, SEEK_CUR);
				break;
			}
			}
		}
		default: {
			if (debug) {
				fprintf(stderr, "Unhandled type %u\n", header.type);
			}
		}
		}
	}
	gzclose(file);

	return EXIT_SUCCESS;
}

