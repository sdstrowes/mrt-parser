
#include "mrt.h"
#include "bgp-path-attr.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
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
		inet_ntop(AF_INET6, input+index, buffer, buffer_len);
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

	int output_idx = strlen(buffer);
	int remaining  = buffer_len - output_idx;

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


