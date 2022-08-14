#ifndef __BGP_PATH_ATTR__
#define __BGP_PATH_ATTR__

#include <stdint.h>

int parse_bgp_path_attr_mp_reach_nlri(char *buffer, int buffer_len, uint8_t *input, int len);
int parse_bgp_path_attr_community(char *buffer, int buffer_len, uint8_t *input, int len);
int parse_bgp_path_attr_nexthop(char *buffer, int remaining, uint8_t *input, int len);
int parse_bgp_path_attr_aspath(char *buffer, int remaining, uint8_t *input, int len);

#endif

