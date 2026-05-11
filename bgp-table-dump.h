#ifndef __BGP_TABLE_DUMP__
#define __BGP_TABLE_DUMP__

#include <stdbool.h>
#include <stdint.h>

struct output_buffers {
	char *aspath;
	int   aspath_cap;
	char *communities;
	int   communities_cap;
	char *large_communities;
	int   large_communities_cap;
};

int parse_entry(struct spec *spec, struct output_buffers *bufs, bool addpath, int family, struct peer *peer, uint32_t mrt_timestamp, uint8_t *input, int input_len, char *net, uint16_t pfxlen);
int parse_ipvN_unicast(struct spec *spec, struct output_buffers *bufs, bool addpath, struct peer *peer_index, uint8_t *input, int input_len, uint32_t mrt_timestamp, int family);

#endif
