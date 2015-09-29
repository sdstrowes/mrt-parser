#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
   1 byte type, 1 byte count; V2 ASNs are 4 bytes; N of these entries up
   to 'len' bytes in the attribute
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
      |    type == ASPATH_AS_SE[TQ]   |    Count = num ASNs           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
int parse_bgp_path_attr_aspath(uint8_t *input, int len)
{
	int index = 0;
	while (index < len) {
		struct attr_as_path_header header;
		memcpy(&header, input+index, sizeof(header));
		index += sizeof(header);

		if (debug) {
			printf("\n--- BGP PATH ATTR AS PATH ---\n");
			print_hex(&header, 0, sizeof(header));
			printf(" type:%u\n",  header.type);
			printf(" count:%u\n", header.count);
		}

		uint32_t asn;
		int counter = 0;
		if (header.type ==  ASPATH_AS_SET) {
			while (counter < header.count) {
				memcpy(&asn, input+index, sizeof(asn));
				if (counter == 0) {
					printf(" {");
				}
				else {
					printf(",");
				}
				printf("%u", htonl(asn));
				index += sizeof(asn);
				counter++;
			}
			printf("}");
		}
		else if (header.type == ASPATH_AS_SEQ) {
			while (counter < header.count) {
				memcpy(&asn, input+index, sizeof(asn));
				printf(" %u", htonl(asn));
				index += sizeof(asn);
				counter++;
			}
		}
	}
	printf("\n");
	return index;
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
	header.peer_idx = htons(header.peer_idx);
	header.orig_ts  = htonl(header.orig_ts);
	header.attr_len = htons(header.attr_len);

	index += sizeof(header);

	if (debug) {
		printf("\n--- TABLE_DUMP_V2 IPv6 UNICAST ENTRY HEADER ---\n");
		print_hex(&header, 0, sizeof(header));
		printf(" peer_index:%u\n", header.peer_idx);
		printf(" orig_ts: %u\n",   header.orig_ts);
		printf(" attr_len: %u\n",  header.attr_len);
	}

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
		case BGP_PATH_ATTR_ASPATH: {
			int rc = parse_bgp_path_attr_aspath(input+index, attr_header.len);
			if (rc != attr_header.len) {
				fprintf(stderr, "AS_PATH attribute incorrect length: parsed %u, expected %u\n",
					rc, attr_header.len);
			}
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
int parse_ipv6_unicast(uint8_t *input)
{
	int index = 0;

	uint32_t seq_no;
	uint8_t  pfx_len;
	char out_str[INET6_ADDRSTRLEN];
	uint16_t entries_count;

	memcpy(&seq_no, input, sizeof(seq_no));
	seq_no = htonl(seq_no);
	index += sizeof(seq_no);

	pfx_len = input[index];
	index += sizeof(pfx_len);

	uint8_t num_bytes = 0;
	int tmp = pfx_len;
	while (tmp > 0) {num_bytes++; tmp-=8;}

	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(struct sockaddr_in6));
	memcpy(&addr.sin6_addr, input+index, num_bytes);
	index += num_bytes;

	memset(out_str, 0, INET_ADDRSTRLEN);
	inet_ntop(AF_INET6, &addr.sin6_addr, out_str, INET6_ADDRSTRLEN);

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
	FILE *file = NULL;
	debug = false;

	int opt;
	while ((opt = getopt(argc, argv, "df:h")) != -1) {
		switch (opt) {
		case 'd': {
			debug = true;
			fprintf(stderr, "Enabled debug\n");
			break;
		}
		case 'f': {
			file = fopen(optarg, "r");
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

	struct mrt_header header;
	while (fread(&header, sizeof(struct mrt_header), 1, file) == 1) {
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
			case TABLE_DUMP_V2_RIB_IPV6_UNICAST: {
				uint8_t *input = (uint8_t *)malloc(header.length);
				fread(input, header.length, 1, file);
				uint32_t bytes_parsed = parse_ipv6_unicast(input);
				free(input);

				if (bytes_parsed != header.length) {
					printf("Error: parsed %u bytes from a header length %u\n",
						bytes_parsed, header.length);
					exit(EXIT_FAILURE);
				}

				break;
			}
			default: {
				if (debug) {
					printf("Unhandled subtype %u\n", header.subtype);
				}
				fseek(file, header.length, SEEK_CUR);
			}
			}
			break;
		}
		default: {
			printf("Unhandled type %u\n", header.subtype);
		}
		}
	}
	fclose(file);

	return EXIT_SUCCESS;
}

