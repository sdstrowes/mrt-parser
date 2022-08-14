#ifndef __MRT_PARSER_TYPES_H__
#define __MRT_PARSER_TYPES_H__

enum origin {ORIGIN_UNKNOWN, IGP, EGP, INCOMPLETE};


char *origin_str(enum origin origin);

enum as_path {SEGMENTTYPE_UNKNOWN, SET, SEQ};

#endif

