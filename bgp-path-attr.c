
#include "mrt.h"
#include "bgp-path-attr.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

extern bool debug;

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

//	struct nlri outputs[256];
//	memset(outputs, 0, sizeof (struct nlri)*256);

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

			int n = sprintf(buffer_idx, "%s/%u", addr_str, nlri_len);
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

			int n = sprintf(buffer_idx, "%s/%u", addr_str, nlri_len);
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
	int i = 0;
	char *buffer_idx = buffer;
	int remaining = buffer_len;
	while (idx < len) {
		uint16_t *a, *b;
		a = (uint16_t *)(input+idx);
		*a = htons(*a);
		idx += 2;
		b = (uint16_t *)(input+idx);
		*b = htons(*b);
		idx += 2;

		if (i != 0) {
			int rc = snprintf(buffer_idx, remaining, " %u:%u", *a, *b);
			if (rc < 0) {
				printf("ERROR: Cannot write community\n");
			}
			else if (rc >= remaining) {
				printf("ERROR: Not enough space in buffer for community\n");
			}
			buffer_idx += rc;
			remaining  -= rc;
		}
		else {
			int rc = snprintf(buffer_idx, remaining, "%u:%u", *a, *b);
			if (rc < 0) {
				printf("ERROR: Cannot write community\n");
			}
			else if (rc >= remaining) {
				printf("ERROR: Not enough space in buffer for community\n");
			}
			buffer_idx += rc;
			remaining  -= rc;
		}

		i++;
	}

	return len;
}

int parse_bgp_path_attr_nexthop(char *buffer, int remaining, uint8_t *input, int len)
{
	if (remaining < len) {
		fprintf(stderr, "parse_bgp_path_attr_nexthop: remaining (%u) < len (%u)\n", remaining, len);
		return -1;
	}
	if (len == 4) {
		inet_ntop(AF_INET, input, buffer, INET_ADDRSTRLEN);
	}
	else if (len == 16) {
		inet_ntop(AF_INET6, input, buffer, INET6_ADDRSTRLEN);
	}

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
					n = sprintf(buffer_idx, " {%u", htonl(*asn));
					buffer_idx += n;
					remaining  -= n;
					idx += sizeof(uint32_t);
					hop_count++;
				}
				else {
					n = sprintf(buffer_idx, ",%u", htonl(*asn));
					buffer_idx += n;
					remaining  -= n;
					idx += sizeof(uint32_t);
					hop_count++;
				}
			}
			sprintf(buffer_idx, "}");
			buffer_idx++;
			remaining--;
		}
		else if (header.type == ASPATH_AS_SEQ) {
			while (hop_count < header.count) {
				asn = (uint32_t *)(input+idx);
				if (strlen(buffer) > 0) {
					n = sprintf(buffer_idx, " %u", htonl(*asn));
				}
				else {
					n = sprintf(buffer_idx, "%u", htonl(*asn));
				}
				buffer_idx += n;
				remaining  -= n;
				idx += sizeof(uint32_t);
				hop_count++;
			}
		}
	}

	return idx;
}


