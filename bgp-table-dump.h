#ifndef __BGP_TABLE_DUMP__
#define __BGP_TABLE_DUMP__

#include <stdbool.h>
#include <stdint.h>

struct entry_buffers {
	char *aspath;
	int   aspath_size;
	char *communities;
	int   communities_size;
};

int parse_entry(struct spec *spec, bool addpath, int family, struct peer *peer, uint32_t mrt_timestamp, uint8_t *input, int input_len, char *net, uint16_t pfxlen, struct entry_buffers *bufs);
int parse_ipvN_unicast(struct spec *spec, bool addpath, struct peer *peer_index, uint8_t *input, int input_len, uint32_t mrt_timestamp, int family);

#endif

