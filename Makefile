CC      = cc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lz
TARGET  = mrt-parser
SRCS    = mrt.c bgp-path-attr.c bgp-table-dump.c input.c mrt-parser-types.c
OBJS    = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: clean
