
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mrt.h"
#include "bgp-path-attr.h"
#include "mrt-parser-types.h"

extern bool debug;

/* Entries are of either these forms: */

/* rfc8050 (addpath)
   2 bytes, 4 bytes, 4 bytes, 2 bytes:
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |    Peer Index =  15           |    Originated ...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |    ... time                   |    Path ...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           ... identifier             | Attribute Length              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   2 bytes, 4 bytes, 2 bytes:
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
      |    Peer Index =  15           |    Originated ...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           ... time                   | Attribute Length              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
int parse_entry(struct spec *spec, bool addpath, int family, struct peer *peer, uint32_t mrt_timestamp, uint8_t *input, int input_len, char *net, uint16_t pfxlen)
{
	struct table_dump_v2_ipv6_unicast_header header;
	uint16_t index = 0;
	int sizeof_header;

	if (addpath) {
		struct table_dump_v2_ipv6_unicast_addpath_header header_tmp;

		memcpy(&header_tmp, input, sizeof(header_tmp));
		header_tmp.attr_len = htons(header_tmp.attr_len);

		index += sizeof(header_tmp);

		header_tmp.peer_idx = htons(header_tmp.peer_idx);
		header_tmp.orig_ts  = htonl(header_tmp.orig_ts);

		if (debug) {
			printf("\n--- TABLE_DUMP_V2 IPv6 UNICAST ENTRY HEADER ---\n");
			print_hex(&header_tmp, 0, sizeof(header_tmp));
			printf(" peer_index:%u\n", header_tmp.peer_idx);
			printf(" orig_ts: %u\n",   header_tmp.orig_ts);
			printf(" path_id: %u\n",   header_tmp.path_id);
			printf(" attr_len: %lu + %u\n", sizeof(header_tmp), header_tmp.attr_len);
		}

		header.peer_idx = header_tmp.peer_idx;
		header.orig_ts  = header_tmp.orig_ts;
		header.attr_len = header_tmp.attr_len;

		sizeof_header = sizeof(header_tmp);
	}
	else {
		memcpy(&header, input, sizeof(header));
		header.attr_len = htons(header.attr_len);

		index += sizeof(header);

		header.peer_idx = htons(header.peer_idx);
		header.orig_ts  = htonl(header.orig_ts);

		if (debug) {
			printf("\n--- TABLE_DUMP_V2 IPv6 UNICAST ENTRY HEADER ---\n");
			print_hex(&header, 0, sizeof(header));
			printf(" peer_index:%u\n", header.peer_idx);
			printf(" orig_ts: %u\n",   header.orig_ts);
			printf(" attr_len: %lu + %u\n", sizeof(header), header.attr_len);
		}

		sizeof_header = sizeof(header);
	}

	/* Common entries */
	uint16_t mask = BGP_PATH_ATTR_ORIGIN_MASK |
			BGP_PATH_ATTR_ASPATH_MASK |
			BGP_PATH_ATTR_NEXTHOP_MASK |
			BGP_PATH_ATTR_EXITDISC_MASK |
			BGP_PATH_ATTR_COMMUNITY_MASK |
			BGP_PATH_ATTR_MP_REACH_NLRI_MASK;

	int buf_len = 512;

	char *aspath_buffer = NULL;
	char *nexthop_buffer = NULL;
	char *communities_buffer = NULL;
	char  agg_nag[4];
	char *agg_buffer = NULL;
	char *nlri_buffer = NULL;

	agg_nag[0] = '\0';

	enum origin origin = ORIGIN_UNKNOWN;
	uint32_t exitdisc = 0;

	while (index < sizeof_header + header.attr_len) {
		struct bgp_attr_header attr_header;

		attr_header.flags = input[index];
		index++;
		attr_header.code  = input[index];
		index++;

		// Bit hacky: header field isn't always the same length.
		//   uint8_t flags;
		//   uint8_t code;
		//   uint8_t or uint16_t len
		if (attr_header.flags & 0x10) {
			uint16_t *len = (uint16_t *)(input + index);
			attr_header.len = ntohs(*len);
			index += 2;
		}
		else {
			attr_header.len = *(input + index);
			index += 1;
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
				printf("Skipping PATH_ATTR_ORIGIN type:%u, length:%u\n", attr_header.code, attr_header.len);
			}
			/* Clear mask */
			mask -= BGP_PATH_ATTR_ORIGIN_MASK;

			uint8_t tmp = input[index];
			switch(tmp) {
			case 0: {
				origin = IGP;
				break;
			}
			case 1: {
				origin = EGP;
				break;
			}
			case 2: {
				origin = INCOMPLETE;
				break;
			}
			}


			break;
		}
		case BGP_PATH_ATTR_ASPATH: {
		/* Columnar output needs to be consistent; if we expect a column in the
		 * mask but it's not present in the data, add columns */
			if (spec->aspath) {
				aspath_buffer = (char *)malloc(buf_len);
				aspath_buffer[0] = '\0';
				int rc = parse_bgp_path_attr_aspath(&aspath_buffer, buf_len, input+index, attr_header.len, spec->aspath_hex);
				if (rc != attr_header.len) {
					fprintf(stderr, "AS_PATH attribute incorrect length: parsed %u, expected %u\n",
						rc, attr_header.len);
				}
			}
			break;
		}
		case BGP_PATH_ATTR_NEXTHOP: {
			nexthop_buffer = (char *)malloc(INET6_ADDRSTRLEN);
			if (nexthop_buffer == NULL) {
				fprintf(stderr, "malloc failed\n");
				exit(1);
			}
			nexthop_buffer[0] = '\0';
			int rc = parse_bgp_path_attr_nexthop(nexthop_buffer, buf_len, input+index, attr_header.len);
			if (rc != attr_header.len) {
				fprintf(stderr, "NEXTHOP attribute incorrect length: parsed %u, expected %u\n",
					rc, attr_header.len);
				return -1;
			}
			break;
		}
		case BGP_PATH_ATTR_EXITDISC: {
			memcpy(&exitdisc, input+index, attr_header.len);
			exitdisc = htonl(exitdisc);

			break;
		}
		case BGP_PATH_ATTR_LOCALPREF: {
			if (debug) {
				printf("Skipping PATH_ATTR_LOCALPREF type:%u, length:%u\n", attr_header.code, attr_header.len);
			}
			break;
		}
		case BGP_PATH_ATTR_ATOM_AGG: {
			strncpy(agg_nag, "AG", sizeof(agg_nag));

			break;
		}
		case BGP_PATH_ATTR_AGGREGATOR: {
			//  AGGREGATOR is an optional transitive attribute of length 6.
			//  The attribute contains the last AS number that formed the
			//  aggregate route (encoded as 2 octets), followed by the IP
			//  address of the BGP speaker that formed the aggregate route
			//  (encoded as 4 octets).

			if (debug) {
				printf("PATH_ATTR_AGGREGATOR type:%u, length:%u\n", attr_header.code, attr_header.len);
				print_hex(input+index, 0, 8);
			}

			uint32_t asn;
			memcpy(&asn, input+index, 4);
			asn = htonl(asn);

			char addr_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, input+index+4, addr_str, INET_ADDRSTRLEN);

			// This should never be more than INET_ADDRSTRLEN
			// (which includes null), plus length of a 32-bit
			// decimal encoded int + a space + null
			const int agg_buffer_len = INET_ADDRSTRLEN + 10 + 1 + 1;
			agg_buffer = (char *)malloc(agg_buffer_len);
			memset(agg_buffer, '\0', agg_buffer_len);
			sprintf(agg_buffer, "%u %s", asn, addr_str);

			break;
		}
		case BGP_PATH_ATTR_AS4_AGGREGATOR: {
			printf("Unhandled AS4_AGGREGATOR attribute\n");

			break;
		}

		case BGP_PATH_ATTR_COMMUNITY: {
			if (spec->communities) {
				communities_buffer = (char *)malloc(buf_len);
				communities_buffer[0] = '\0';
				int rc = parse_bgp_path_attr_community(&communities_buffer, buf_len, input+index, attr_header.len, spec->communities_hex);
				if (rc != attr_header.len) {
					printf("BGP_PATH_ATTR_COMMUNITY attribute incorrect length: parsed %u, expected %u\n",
						rc, attr_header.len);
				}
			}
			break;
		}
		case BGP_PATH_ATTR_MP_REACH_NLRI: {
//			if (debug) {
//				printf("Unhandled MP_REACH_NLRI\n");
//			}
			nlri_buffer = (char *)malloc(buf_len);
			nlri_buffer[0] = '\0';
			int rc = parse_bgp_path_attr_mp_reach_nlri(nlri_buffer, buf_len, input+index, family, attr_header.len);
			if (rc != attr_header.len) {
				printf("MP_REACH_NLRI attribute incorrect length: parsed %u, expected %u\n",
					rc, attr_header.len);
				fprintf(stderr, "MP_REACH_NLRI attribute incorrect length: parsed %u, expected %u\n",
					rc, attr_header.len);
			}
			//mask -= BGP_PATH_ATTR_MP_REACH_NLRI_MASK;
			//printf("mp_reach_nlri: %s\n", nlri_buffer);
			break;
		}
		case BGP_PATH_ATTR_LARGE_COMMUNITY: {
			uint32_t a;
			uint32_t b;
			uint32_t c;

			memcpy(&a, input+index, 4);
			memcpy(&b, input+index+4, 4);
			memcpy(&c, input+index+8, 4);

			fprintf(stderr, "Not yet parsing large community: %08x %08x %08x\n", a, b, c);

			break;
		}
		default: {
			if (debug) {
				printf("Skipping unrecognised type:%u, length:%u\n", attr_header.code, attr_header.len);
			}
		}
		}

		index += attr_header.len;
	}

	char *nexthop = NULL;
	if (nexthop_buffer != NULL) {
		nexthop = nexthop_buffer;
	}
	else if (nlri_buffer != NULL) {
		nexthop = nlri_buffer;
	}

	printf("TABLE_DUMP2|%u|B|%s|%u|%s/%u|%s|%s|%s|0|%u|%s|%s|%s|\n",
		mrt_timestamp,
		peer[header.peer_idx].ip_addr,
		peer[header.peer_idx].asn,
		net, pfxlen,
		aspath_buffer == NULL ? "" : aspath_buffer,
		origin_str(origin),
		nexthop == NULL ? "" : nexthop,
		exitdisc,
		communities_buffer == NULL ? "" : communities_buffer,
		strlen(agg_nag) ? agg_nag : "NAG",
		agg_buffer == NULL ? "" : agg_buffer );

	if (aspath_buffer      != NULL) { free(aspath_buffer);      aspath_buffer = NULL;     }
	if (nexthop_buffer     != NULL) { free(nexthop_buffer);     nexthop_buffer = NULL;    }
	if (agg_buffer         != NULL) { free(agg_buffer);         agg_buffer = NULL;        }
	if (communities_buffer != NULL) { free(communities_buffer); communities_buffer = NULL;}
	if (nlri_buffer        != NULL) { free(nlri_buffer);        nlri_buffer = NULL;       }

	if (index != sizeof_header + header.attr_len) {
		printf("Error: Bad length detected in IPv6 unicast entry: %u != %u\n",
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
int parse_ipvN_unicast(struct spec *spec, bool addpath, struct peer *peer_index, uint8_t *input, int input_len, uint32_t mrt_timestamp, int family)
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

	if (family == TABLE_DUMP_V2_RIB_IPV6_UNICAST || family == TABLE_DUMP_V2_RIB_IPV6_UNICAST_ADDPATH) {
		struct in6_addr addr;
		memset(&addr, 0, sizeof(struct in6_addr));
		memcpy(&addr, input+index, num_bytes);
		memset(out_str, 0, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &addr, out_str, INET6_ADDRSTRLEN);
	}
	else if (family == TABLE_DUMP_V2_RIB_IPV4_UNICAST || family == TABLE_DUMP_V2_RIB_IPV4_UNICAST_ADDPATH) {
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
		int rc = parse_entry(spec, addpath, family, peer_index, mrt_timestamp, input+index, input_len-index, out_str, pfx_len);
		if (rc == -1) {
			fprintf(stderr, "parse_entry() failed\n");
			return -1;
		}
		index += rc;
	}

	return index;
}

