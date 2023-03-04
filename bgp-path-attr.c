
#include "mrt.h"
#include "bgp-path-attr.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

extern bool debug;

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

	int output_idx = strlen(buffer);

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

			char addr_str[INET_ADDRSTRLEN];
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
			char addr_str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, input+index, buffer, INET6_ADDRSTRLEN);

			index += nexthop_addr_len;

			break;
		}
		default: {
			fprintf(stderr, "[%3u] Unknown AF type in NLRI information: %u\n", index, family);
			return index;
		}
	}

//	if (index != len) {
//		fprintf(stderr, "bad NLRI read?\n");
//	}

//	return index;
	return len;
}


int parse_bgp_path_attr_community(char **buffer_ptr, int buffer_size, uint8_t *input, int input_size, bool as_hex)
{
	if (input_size % 4 != 0) {
		fprintf(stderr, "Malformed community of length %u\n", input_size);
	}

	char *buffer = *buffer_ptr;
	int input_idx = 0;
	int output_idx = 0;
	int remaining = buffer_size;
	int i = 0, rc;

	while (input_idx < input_size) {

		// add extra buffer space if low
		if (remaining < 16) {  // arbitrary
			char *tmp = (char *)realloc(buffer, buffer_size + 256);
			if (tmp == NULL) {
				fprintf(stderr, "ERROR: realloc() failed\n");
			}
			else {
				memset(tmp+buffer_size, '\0', 256);
				remaining += 256;
				buffer_size += 256;
				buffer = tmp;
				*buffer_ptr = tmp;
			}
		}

		uint16_t *a, *b;
		a = (uint16_t *)(input+input_idx);
		*a = htons(*a);
		input_idx += 2;
		b = (uint16_t *)(input+input_idx);
		*b = htons(*b);
		input_idx += 2;

		if (as_hex) {
			rc = snprintf(buffer+output_idx, remaining, "%04x:%04x ", *a, *b);
		}
		else {
			rc = snprintf(buffer+output_idx, remaining, "%u:%u ", *a, *b);
		}
		if (rc < 0) {
			printf("ERROR: Cannot write community\n");
		}
		else if (rc >= remaining) {
			printf("ERROR: Not enough space in buffer for community\n");
		}

		output_idx += rc;
		remaining  -= rc;

		if (remaining < 0) {
			// This should never happen, but bail if somehow we get here
			return input_idx;
		}

		i++;
	}

	// remove the trailing space
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
int parse_bgp_path_attr_aspath(char **buffer_ptr, int buffer_size, uint8_t *input, int len, bool as_hex)
{
	int idx = 0;
	char *buffer = *buffer_ptr;
	int buffer_idx = 0;
	int remaining  = buffer_size;

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
				if (remaining < 16) {  // arbitrary
					char *tmp;
					tmp = (char *)realloc(buffer, buffer_size + 256);
					if (tmp == NULL) {
						fprintf(stderr, "ERROR: realloc() failed\n");
					}
					else {
						memset(tmp+buffer_size, '\0', 256);
						remaining += 256;
						buffer_size += 256;
						buffer = tmp;
						*buffer_ptr = tmp;
					}
				}

				asn = (uint32_t *)(input+idx);
				if (hop_count == 0) {
					if (as_hex) {
						n = snprintf(buffer + buffer_idx, remaining, " {%08x", htonl(*asn));
					}
					else {
						n = snprintf(buffer + buffer_idx, remaining, " {%u", htonl(*asn));
					}
					if (n < 0) {
						fprintf(stderr, "ERROR: snprintf() failed\n");
					}
					else if (n >= remaining) {
						printf("WARNING: AS path truncated\n");
					}
					buffer_idx += n;
					remaining  -= n;
					if (remaining < 0) {remaining = 0;}
					idx += sizeof(uint32_t);
					hop_count++;
				}
				else {
					if (as_hex) {
						n = snprintf(buffer + buffer_idx, remaining, ",%08x", htonl(*asn));
					}
					else {
						n = snprintf(buffer + buffer_idx, remaining, ",%u", htonl(*asn));
					}
					if (n < 0) {
						fprintf(stderr, "ERROR: snprintf() failed\n");
					}
					else if (n >= remaining) {
						printf("WARNING: AS path truncated\n");
					}
					buffer_idx += n;
					remaining  -= n;
					if (remaining < 0) {remaining = 0;}
					idx += sizeof(uint32_t);
					hop_count++;
				}
			}
			snprintf(buffer + buffer_idx, remaining, "}");
			buffer_idx++;
			remaining--;
		}
		else if (header.type == ASPATH_AS_SEQ) {
			while (hop_count < header.count) {

				if (remaining < 16) {  // arbitrary
					char *tmp;
					tmp = (char *)realloc(buffer, buffer_size + 256);
					if (tmp == NULL) {
						fprintf(stderr, "ERROR: realloc() failed\n");
					}
					else {
						memset(tmp+buffer_size, '\0', 256);
						remaining += 256;
						buffer_size += 256;
						buffer = tmp;
						*buffer_ptr = tmp;
					}
				}

				asn = (uint32_t *)(input+idx);
				if (buffer_idx > 0) {
					if (as_hex) {
						n = snprintf(buffer + buffer_idx, remaining, " %08x", htonl(*asn));
					}
					else {
						n = snprintf(buffer + buffer_idx, remaining, " %u", htonl(*asn));
					}
				}
				else {
					if (as_hex) {
						n = snprintf(buffer + buffer_idx, remaining, "%08x", htonl(*asn));
					}
					else {
						n = snprintf(buffer + buffer_idx, remaining, "%u", htonl(*asn));
					}
				}
				if (n < 0) {
					fprintf(stderr, "ERROR: snprintf() failed\n");
				}
				else if (n >= remaining) {
					printf("WARNING: AS path truncated\n");
				}
				buffer_idx += n;
				remaining  -= n;
				if (remaining < 0) {remaining = 0;}
				idx += sizeof(uint32_t);
				hop_count++;
			}
		}
	}

	return idx;
}


