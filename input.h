#ifndef __INPUT_H__
#define __INPUT_H__


#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>

struct mrt_fd {
	bool is_mmap;
	gzFile file;
	char *mmap;
	size_t length;
	size_t i;
};

int mrt_open(struct mrt_fd **fd, bool is_mmap, char *fn);
int mrt_read(struct mrt_fd *fd, void *buffer, unsigned int len);
void mrt_seek(struct mrt_fd *fd, uint32_t delta);
int mrt_close(struct mrt_fd **fd);


#endif

