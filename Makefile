CC      = cc
CFLAGS  = -Wall -Wextra -O3 -march=native -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib -ldeflate

TARGET  = mrt-parser
SRCS    = mrt.c bgp-path-attr.c bgp-table-dump.c mrt-parser-types.c
OBJS    = $(SRCS:.c=.o)

HDRS    = mrt.h bgp-path-attr.h bgp-table-dump.h mrt-parser-types.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

mrt.o:              mrt.c              mrt.h bgp-path-attr.h bgp-table-dump.h mrt-parser-types.h
bgp-path-attr.o:    bgp-path-attr.c    mrt.h bgp-path-attr.h
bgp-table-dump.o:   bgp-table-dump.c   mrt.h bgp-path-attr.h bgp-table-dump.h mrt-parser-types.h
mrt-parser-types.o: mrt-parser-types.c mrt-parser-types.h

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
