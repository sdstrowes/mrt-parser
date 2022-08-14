#ifndef __BGP_TABLE_DUMP__
#define __BGP_TABLE_DUMP__

#include <stdbool.h>
#include <stdint.h>


int parse_entry(bool addpath, struct peer *peer, uint32_t mrt_timestamp, uint8_t *input, int input_len, char *net, uint16_t pfxlen);
int parse_ipvN_unicast(bool addpath, struct peer *peer_index, uint8_t *input, int input_len, uint32_t mrt_timestamp, int family);

#endif

