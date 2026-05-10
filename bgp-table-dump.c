
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mrt.h"
#include "bgp-path-attr.h"
#include "bgp-table-dump.h"
#include "mrt-parser-types.h"

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
int parse_entry(struct spec *spec, bool addpath, int family, struct peer *peer,
                uint32_t mrt_timestamp, uint8_t *input, int input_len,
                char *net, uint16_t pfxlen, struct entry_buffers *bufs)
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

	char *aspath_out      = NULL;
	char *communities_out = NULL;
	char  nexthop_buf[INET6_ADDRSTRLEN] = {'\0'};
	char  nlri_buf[INET6_ADDRSTRLEN]    = {'\0'};
	char  agg_nag[4]                    = {'\0'};
	char  agg_buf[INET_ADDRSTRLEN + 12] = {'\0'};
	bool  has_nexthop = false;
	bool  has_nlri    = false;
	bool  has_agg     = false;

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
			uint8_t tmp = input[index];
			switch(tmp) {
			case 0: origin = IGP;        break;
			case 1: origin = EGP;        break;
			case 2: origin = INCOMPLETE; break;
			}
			break;
		}
		case BGP_PATH_ATTR_ASPATH: {
			if (spec->aspath) {
				if (bufs->aspath == NULL) {
					bufs->aspath = (char *)malloc(512);
					bufs->aspath_size = 512;
				}
				bufs->aspath[0] = '\0';
				int rc = parse_bgp_path_attr_aspath(&bufs->aspath, &bufs->aspath_size, input+index, attr_header.len, spec->aspath_hex);
				if (rc != attr_header.len) {
					fprintf(stderr, "AS_PATH attribute incorrect length: parsed %u, expected %u\n",
						rc, attr_header.len);
				}
				aspath_out = bufs->aspath;
			}
			break;
		}
		case BGP_PATH_ATTR_NEXTHOP: {
			int rc = parse_bgp_path_attr_nexthop(nexthop_buf, INET6_ADDRSTRLEN, input+index, attr_header.len);
			if (rc != attr_header.len) {
				fprintf(stderr, "NEXTHOP attribute incorrect length: parsed %u, expected %u\n",
					rc, attr_header.len);
				return -1;
			}
			has_nexthop = true;
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
			if (debug) {
				printf("PATH_ATTR_AGGREGATOR type:%u, length:%u\n", attr_header.code, attr_header.len);
				print_hex(input+index, 0, 8);
			}

			uint32_t asn;
			memcpy(&asn, input+index, 4);
			asn = htonl(asn);

			char addr_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, input+index+4, addr_str, INET_ADDRSTRLEN);

			sprintf(agg_buf, "%u %s", asn, addr_str);
			has_agg = true;
			break;
		}
		case BGP_PATH_ATTR_AS4_AGGREGATOR: {
			printf("Unhandled AS4_AGGREGATOR attribute\n");
			break;
		}
		case BGP_PATH_ATTR_COMMUNITY: {
			if (spec->communities) {
				if (bufs->communities == NULL) {
					bufs->communities = (char *)malloc(512);
					bufs->communities_size = 512;
				}
				bufs->communities[0] = '\0';
				int rc = parse_bgp_path_attr_community(&bufs->communities, &bufs->communities_size, input+index, attr_header.len, spec->communities_hex);
				if (rc != attr_header.len) {
					printf("BGP_PATH_ATTR_COMMUNITY attribute incorrect length: parsed %u, expected %u\n",
						rc, attr_header.len);
				}
				communities_out = bufs->communities;
			}
			break;
		}
		case BGP_PATH_ATTR_MP_REACH_NLRI: {
			int rc = parse_bgp_path_attr_mp_reach_nlri(nlri_buf, INET6_ADDRSTRLEN, input+index, family, attr_header.len);
			if (rc != attr_header.len) {
				printf("MP_REACH_NLRI attribute incorrect length: parsed %u, expected %u\n",
					rc, attr_header.len);
				fprintf(stderr, "MP_REACH_NLRI attribute incorrect length: parsed %u, expected %u\n",
					rc, attr_header.len);
			}
			has_nlri = true;
			break;
		}
		case BGP_PATH_ATTR_LARGE_COMMUNITY: {
			// not yet parsed
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

	char *nexthop = has_nexthop ? nexthop_buf : (has_nlri ? nlri_buf : "");

	/* Build the output line in segments to avoid printf overhead. */
	char seg[256];
	int n = 0;
	const char *peer_ip = peer[header.peer_idx].ip_addr;

	memcpy(seg + n, "TABLE_DUMP2|", 12);    n += 12;
	n += uint32_to_dec(seg + n, mrt_timestamp);
	memcpy(seg + n, "|B|", 3);              n += 3;
	size_t slen = strlen(peer_ip);
	memcpy(seg + n, peer_ip, slen);         n += slen;
	seg[n++] = '|';
	n += uint32_to_dec(seg + n, peer[header.peer_idx].asn);
	seg[n++] = '|';
	slen = strlen(net);
	memcpy(seg + n, net, slen);             n += slen;
	seg[n++] = '/';
	n += uint32_to_dec(seg + n, pfxlen);
	seg[n++] = '|';
	fwrite(seg, 1, n, stdout);

	if (aspath_out) fwrite(aspath_out, 1, strlen(aspath_out), stdout);

	n = 0;
	const char *os = origin_str(origin);
	seg[n++] = '|';
	slen = strlen(os);
	memcpy(seg + n, os, slen);              n += slen;
	seg[n++] = '|';
	slen = strlen(nexthop);
	memcpy(seg + n, nexthop, slen);         n += slen;
	memcpy(seg + n, "|0|", 3);              n += 3;
	n += uint32_to_dec(seg + n, exitdisc);
	seg[n++] = '|';
	fwrite(seg, 1, n, stdout);

	if (communities_out) fwrite(communities_out, 1, strlen(communities_out), stdout);

	n = 0;
	seg[n++] = '|';
	if (agg_nag[0]) { memcpy(seg + n, agg_nag, 2); n += 2; }
	else             { memcpy(seg + n, "NAG", 3);   n += 3; }
	seg[n++] = '|';
	if (has_agg) { slen = strlen(agg_buf); memcpy(seg + n, agg_buf, slen); n += slen; }
	memcpy(seg + n, "|\n", 2);              n += 2;
	fwrite(seg, 1, n, stdout);

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

	uint8_t num_bytes = (pfx_len + 7) / 8;

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

	struct entry_buffers bufs = {NULL, 0, NULL, 0};

	uint16_t i;
	for (i = 0; i < entries_count; i++) {
		int rc = parse_entry(spec, addpath, family, peer_index, mrt_timestamp, input+index, input_len-index, out_str, pfx_len, &bufs);
		if (rc == -1) {
			fprintf(stderr, "parse_entry() failed\n");
			if (bufs.aspath)      free(bufs.aspath);
			if (bufs.communities) free(bufs.communities);
			return -1;
		}
		index += rc;
	}

	if (bufs.aspath)      free(bufs.aspath);
	if (bufs.communities) free(bufs.communities);

	return index;
}
