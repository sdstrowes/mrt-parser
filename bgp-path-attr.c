
#include "mrt.h"
#include "bgp-path-attr.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

extern bool debug;

static int uint32_to_dec(char *buf, uint32_t val)
{
	if (val == 0) { buf[0] = '0'; return 1; }
	char tmp[10];
	int n = 0;
	while (val) { tmp[n++] = '0' + (val % 10); val /= 10; }
	for (int i = 0; i < n; i++) buf[i] = tmp[n-1-i];
	return n;
}

static int uint32_to_hex8(char *buf, uint32_t val)
{
	static const char hex[] = "0123456789abcdef";
	for (int i = 7; i >= 0; i--) { buf[i] = hex[val & 0xf]; val >>= 4; }
	return 8;
}

static int uint16_to_hex4(char *buf, uint16_t val)
{
	static const char hex[] = "0123456789abcdef";
	buf[0] = hex[(val >> 12) & 0xf];
	buf[1] = hex[(val >>  8) & 0xf];
	buf[2] = hex[(val >>  4) & 0xf];
	buf[3] = hex[ val        & 0xf];
	return 4;
}

int parse_bgp_path_attr_mp_reach_nlri(char *buffer, int buffer_len, uint8_t *input, int family, int len)
{
	int index = 0;

	// Regarding NLRI encoding in MRT dumps:
	//
	// https://www.rfc-editor.org/errata/eid6640
	//
	// There is one exception to the encoding of BGP attributes for the BGP
	// MP_REACH_NLRI attribute (BGP Type Code 14) [RFC4760]. Since the AFI,
	// SAFI, and NLRI information is already encoded in the RIB Entry Header
	// or RIB_GENERIC Entry Header, only the Next Hop Address Length and
	// Next Hop Address fields are included. The Reserved field is omitted.
	// The attribute length is also adjusted to reflect only the length of
	// the Next Hop Address Length and Next Hop Address fields.
	//
	// One way of solving this is to compare the attribute length of
	// MP_REACH_NLRI with the first byte of the attribute. If the value of
	// the first byte is equal to the attribute lenght - 1 then it is the
	// RFC encoding else assume that a full MP_REACH_NLRI attribute was
	// dumped in which case the parser needs to skip the first 3 bytes to
	// get to the nexthop.
	if (debug) {
		printf("\n--- BGP PATH ATTR MP REACH NLRI (len:%u) ---\n", len);
		print_hex(input+index, 0, len);
	}

	if (input[0] != len - 1) {
		index += 3;
	}

	uint8_t nexthop_addr_len = *(input+index);
	index += 1;

	if (debug) {
		printf("--- NLRI ---\n");
		printf(" nexthop_addr_len:%u bits\n", nexthop_addr_len);
		printf(" index:%u\n", index);
	}

	switch (family) {
		case TABLE_DUMP_V2_RIB_IPV4_UNICAST:
		case TABLE_DUMP_V2_RIB_IPV4_UNICAST_ADDPATH: {
			if (nexthop_addr_len % 4 != 0) {
				fprintf(stderr, "Bad next hop addr length: %u\n", nexthop_addr_len);
				return index;
			}

			inet_ntop(AF_INET, input+index, buffer, INET_ADDRSTRLEN);

			index += nexthop_addr_len;

			break;
		}
		case TABLE_DUMP_V2_RIB_IPV6_UNICAST:
		case TABLE_DUMP_V2_RIB_IPV6_UNICAST_ADDPATH: {
			if (nexthop_addr_len % 16 != 0) {
				fprintf(stderr, "Bad next hop addr length: %u\n", nexthop_addr_len);
				return index;
			}
			inet_ntop(AF_INET6, input+index, buffer, INET6_ADDRSTRLEN);

			index += nexthop_addr_len;

			break;
		}
		default: {
			fprintf(stderr, "[%3u] Unknown AF type in NLRI information: %u\n", index, family);
			return index;
		}
	}

	return len;
}


int parse_bgp_path_attr_community(char **buffer_ptr, int *buffer_size, uint8_t *input, int input_size, bool as_hex)
{
	if (input_size % 4 != 0) {
		fprintf(stderr, "Malformed community of length %u\n", input_size);
	}

	char *buffer = *buffer_ptr;
	int input_idx = 0;
	int output_idx = 0;
	int remaining = *buffer_size;
	int i = 0, n;

	while (input_idx < input_size) {

		if (remaining < 16) {
			int new_size = *buffer_size * 2;
			char *tmp = (char *)realloc(buffer, new_size);
			if (tmp == NULL) {
				fprintf(stderr, "ERROR: realloc() failed\n");
				return input_idx;
			}
			remaining += new_size - *buffer_size;
			*buffer_size = new_size;
			buffer = tmp;
			*buffer_ptr = tmp;
		}

		uint16_t a, b;
		memcpy(&a, input+input_idx, sizeof(a));
		a = ntohs(a);
		input_idx += 2;
		memcpy(&b, input+input_idx, sizeof(b));
		b = ntohs(b);
		input_idx += 2;

		if (as_hex) {
			n = uint16_to_hex4(buffer+output_idx, a);
			output_idx += n; remaining -= n;
			buffer[output_idx++] = ':'; remaining--;
			n = uint16_to_hex4(buffer+output_idx, b);
			output_idx += n; remaining -= n;
		}
		else {
			n = uint32_to_dec(buffer+output_idx, a);
			output_idx += n; remaining -= n;
			buffer[output_idx++] = ':'; remaining--;
			n = uint32_to_dec(buffer+output_idx, b);
			output_idx += n; remaining -= n;
		}
		buffer[output_idx++] = ' '; remaining--;

		i++;
	}

	if (i > 0) {
		output_idx--;
		buffer[output_idx] = '\0';
	}

	return input_size;
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
int parse_bgp_path_attr_aspath(char **buffer_ptr, int *buffer_size, uint8_t *input, int len, bool as_hex)
{
	int idx = 0;
	char *buffer = *buffer_ptr;
	int buffer_idx = 0;
	int remaining  = *buffer_size;

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

		int hop_count = 0;
		int n;
		if (header.type == ASPATH_AS_SET) {
			while (hop_count < header.count) {
				if (remaining < 16) {
					int new_size = *buffer_size * 2;
					char *tmp = (char *)realloc(buffer, new_size);
					if (tmp == NULL) {
						fprintf(stderr, "ERROR: realloc() failed\n");
						break;
					}
					remaining += new_size - *buffer_size;
					*buffer_size = new_size;
					buffer = tmp;
					*buffer_ptr = tmp;
				}

				uint32_t val = htonl(*(uint32_t *)(input+idx));
				if (hop_count == 0) {
					buffer[buffer_idx++] = ' ';
					buffer[buffer_idx++] = '{';
					remaining -= 2;
				} else {
					buffer[buffer_idx++] = ',';
					remaining--;
				}
				n = as_hex ? uint32_to_hex8(buffer + buffer_idx, val)
				           : uint32_to_dec(buffer + buffer_idx, val);
				buffer_idx += n; remaining -= n;
				idx += sizeof(uint32_t);
				hop_count++;
			}
			buffer[buffer_idx++] = '}';
			remaining--;
		}
		else if (header.type == ASPATH_AS_SEQ) {
			while (hop_count < header.count) {
				if (remaining < 16) {
					int new_size = *buffer_size * 2;
					char *tmp = (char *)realloc(buffer, new_size);
					if (tmp == NULL) {
						fprintf(stderr, "ERROR: realloc() failed\n");
						break;
					}
					remaining += new_size - *buffer_size;
					*buffer_size = new_size;
					buffer = tmp;
					*buffer_ptr = tmp;
				}

				uint32_t val = htonl(*(uint32_t *)(input+idx));
				if (buffer_idx > 0) {
					buffer[buffer_idx++] = ' ';
					remaining--;
				}
				n = as_hex ? uint32_to_hex8(buffer + buffer_idx, val)
				           : uint32_to_dec(buffer + buffer_idx, val);
				buffer_idx += n; remaining -= n;
				idx += sizeof(uint32_t);
				hop_count++;
			}
		}
	}

	buffer[buffer_idx] = '\0';
	return idx;
}
