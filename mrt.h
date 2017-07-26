#ifndef __MRT_H_
#define __MRT_H_

/*
From RFC 6396, Appendix A:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    Timestamp = 1300475700 epoch sec (2011-03-18 19:15:00)     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Type = 13            |         Subtype = 4           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Length = 87                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Sequence Number = 42                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Preflen = 32  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                 Prefix  =  2001:0DB8::/32                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    Entry Count = 1            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    Peer Index =  15           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |Originated Time = 1300475700 epoch sec (2011-03-18 19:15:00)   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Attribute Length  =  68     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   BGP Path Attributes =
*/


// RFC 6396, section 4
#define MRT_OSPFv2        11
#define MRT_TABLE_DUMP    12
#define MRT_TABLE_DUMP_V2 13
#define MRT_BGP4MP        16
#define MRT_BGP4MP_ET     17
#define MRT_ISIS          32
#define MRT_ISIS_ET       33
#define MRT_OSPFv3        48
#define MRT_OSPFv3_ET     49

// RFC 6396, section 4.3
#define TABLE_DUMP_V2_PEER_INDEX_TABLE    1
#define TABLE_DUMP_V2_RIB_IPV4_UNICAST    2
#define TABLE_DUMP_V2_RIB_IPV4_MULTICAST  3
#define TABLE_DUMP_V2_RIB_IPV6_UNICAST    4
#define TABLE_DUMP_V2_RIB_IPV6_MULTICAST  5
#define TABLE_DUMP_V2_RIB_GENERIC         6

// RFC 4271, page 17
#define BGP_PATH_ATTR_ORIGIN     1
#define BGP_PATH_ATTR_ASPATH     2
#define BGP_PATH_ATTR_NEXTHOP    3
#define BGP_PATH_ATTR_EXITDISC   4
#define BGP_PATH_ATTR_LOCALPREF  5
#define BGP_PATH_ATTR_ATOM_AGG   6
#define BGP_PATH_ATTR_AGGREGATOR 7
// rfc4760, page 3
#define BGP_PATH_ATTR_MP_REACH_NLRI 14

// RFC 4271, page 17
#define ASPATH_AS_SET 1
#define ASPATH_AS_SEQ 2

struct mrt_header
{
        uint32_t ts;
        uint16_t type;
        uint16_t subtype;
        uint32_t length;
} __attribute__((packed));


struct table_dump_v2_ipv6_unicast_header
{
	uint16_t peer_idx;
	uint32_t orig_ts;
	uint16_t attr_len;
} __attribute__((packed));

struct bgp_attr_header
{
	uint8_t  flags;
	uint8_t  code;
	uint16_t len;
} __attribute__((packed));

struct attr_as_path_header
{
	uint8_t type;
	uint8_t count;
} __attribute__((packed));

struct attr_mp_reach_afi_safi
{
	uint16_t afi;
	uint8_t  safi;

} __attribute__((packed));
struct attr_mp_reach_nlri
{
	uint16_t afi;
	uint8_t  safi;
	uint8_t  nh_len;
} __attribute__((packed));


void print_hex(void *, int, int);
void print_help(char *);

int parse_bgp_path_attr_aspath(uint8_t *, int);
int parse_entry(uint8_t *);
int parse_ipvN_unicast(uint8_t *, int);

#endif

