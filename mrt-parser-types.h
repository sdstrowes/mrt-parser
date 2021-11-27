enum origin {ORIGIN_UNKNOWN, IGP, EGP, INCOMPLETE};

static char *origin_strs[] = {"ORIGIN_UNKNOWN", "IGP", "EGP", "INCOMPLETE"};

char *origin_str(enum origin origin);
char *origin_str(enum origin origin)
{
	switch (origin) {
	case IGP: {
		return origin_strs[1];
	}
	case EGP: {
		return origin_strs[2];
	}
	case INCOMPLETE: {
		return origin_strs[3];
	}
	default:
		return origin_strs[0];
	}
}

enum as_path {SEGMENTTYPE_UNKNOWN, SET, SEQ};

